/**
 * LumenPlay 设备短码兑换 API（Cloudflare Workers + KV）
 *
 * 解决「激活码怎么进电视」的最后一公里：电视没有可用的剪贴板来源，
 * 长激活码也不可能用遥控器手打。流程（device code flow，Netflix/YouTube 同款）：
 *
 *   1. TV 解锁卡显示 6 位短码并轮询  GET /api/device/poll?c=621741
 *      （首次轮询即登记短码，KV 记录 TTL 30 分钟，之后每次轮询续期）
 *   2. 用户手机扫码打开 https://lumenplay.app/activate.html?m=..&c=621741
 *      在页面上粘贴收到的激活码 → POST /api/device/submit {code, activation}
 *   3. Worker 把激活码写入同一个 KV key（TTL 30 分钟）
 *   4. TV 下一次轮询拿到 activation → 本地 LicenseManager.activate() 自动解锁
 *      （KV 读取后立即删除 = 一次性消费）
 *
 * 发码方一键投递（admin 通道）：发码方在回邮件时打开
 *   https://lumenplay.app/admin.html?c=<短码>&t=<ADMIN_TOKEN>
 * 粘贴激活码点投递 → POST /api/device/admin-deliver。与 submit 的区别：
 *   - 不要求 TV 正在轮询（用户可能还没打开解锁卡），码存到独立的
 *     d:<短码> key（TTL 7 天），TV 下一次 poll（哪怕几天后）取到即消费；
 *   - TV 若恰好在轮询中，同时写入 c:<短码>，下一拍（3 秒内）立即解锁；
 *   - 鉴权走 ADMIN_TOKEN secret（x-admin-token 头或 t= 查询参数），
 *     不限速（令牌私有）。
 *
 * 会话码 → 机器码绑定：已迁出（2026-11-16）。应用内购买改由 license worker 的
 * `/pay/poll` + D1 强一致存储承担（KV 的边缘缓存会让设备付款后干等 40-60 秒），
 * 本 Worker 只服务 TV 扫码流：6 位纯数字短码，人工投码，激活码本身已绑定机器码，
 * 不需要会话级机器码登记。
 *
 * 安全边界：
 *   - 激活码本身是 RSA 签名且绑定机器码，即使短码被猜到也无法伪造激活，
 *     最多把「别人的码」投到这台设备（无效，签名里的机器码不匹配会拒绝）；
 *   - submit 只接受「TV 正在轮询中」的短码（poll 登记过才存在），并把
 *     短码标记为已用，防止重复投递；
 *   - 按 IP 限速，避免逐码扫描。
 *
 * KV 最终一致性说明：写入到同一区域的读通常在 1 秒内可见，全球传播最坏
 * 约 60 秒。TV 每 3 秒轮询一次、用户与电视通常同区域，实际体验是「手机上
 * 点提交，电视几秒内自动解锁」；极端情况下多等一会儿即可。
 */

/* ───────────────────── 类型（仅编译期，不产生运行时开销） ───────────────────── */

export interface Env {
  DEVICE_KV: KVNamespace;
  ADMIN_TOKEN: string;
}

/** c:<短码> 的会话记录；activation 存在 = 码已投递，等 TV 下一拍取走。 */
interface SessionRecord {
  ts?: number;
  activation?: string;
}
/** d:<短码> 的发码方投递记录（TV 不在线时的兜底，TTL 7 天）。 */
interface DeliveredRecord {
  activation: string;
  ts: number;
}
/** 请求体字段一律按 unknown 读入，再交给 String()/校验函数归一，防止伪造类型穿透。 */
interface DeviceBody {
  code?: unknown;
  activation?: unknown;
}

const TTL_SECONDS = 1800;          // 短码有效期 30 分钟
const DELIVERED_TTL_SECONDS = 604800; // 发码方投递的码保留 7 天（TV 可能过几天才开解锁卡）
const MAX_SUBMITS_PER_HOUR = 30;   // 单 IP 每小时提交上限
const MAX_ACTIVATION_LEN = 4096;   // 激活码长度上限（正常 200~400 字符）

// 短码：TV 端 6 位纯数字（遥控器可打）。CODE_RE 仍按 6~20 位小写字母数字校验
// （历史会话码是 12 位随机串，放宽校验避免把旧链接判死），
// MACHINE_RE 随机器码绑定一起删除——本 Worker 不再关心机器码。
const CODE_RE = /^[0-9a-z]{6,20}$/;

const CORS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...CORS,
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }
    if (url.pathname === '/api/device/poll' && request.method === 'GET') {
      return poll(url, env);
    }
    if (url.pathname === '/api/device/submit' && request.method === 'POST') {
      return submit(request, env);
    }
    if (url.pathname === '/api/device/admin-deliver' && request.method === 'POST') {
      return adminDeliver(request, env);
    }
    if (url.pathname === '/api/device/admin-status' && request.method === 'GET') {
      return adminStatus(request, url, env);
    }
    return json({ error: 'not_found' }, 404);
  },
};

/** admin 令牌校验：头 x-admin-token 优先，兼容 t= 查询参数（书签直链用）。 */
function checkAdmin(request: Request, url: URL, env: Env): boolean {
  const expected = (env.ADMIN_TOKEN || '').trim();
  if (!expected) return false; // 未配置 = admin 通道整体关闭
  const got = (
    request.headers.get('x-admin-token') || url.searchParams.get('t') || ''
  ).trim();
  return got.length === expected.length && got === expected;
}

function activationShapeOk(activation: string): boolean {
  if (activation.length < 20 || activation.length > MAX_ACTIVATION_LEN) return false;
  // 本工程的激活码固定是「两段 base64url + 点」；先挡掉明显不是码的内容
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(activation);
}

/**
 * 设备轮询：优先取发码方投递的码（d:），其次登记/续期会话；有码则消费返回。
 */
async function poll(url: URL, env: Env): Promise<Response> {
  const code = (url.searchParams.get('c') || '').trim().toLowerCase();
  if (!CODE_RE.test(code)) return json({ error: 'bad_code' }, 400);

  // 发码方可能早已投递（admin-deliver 不要求 TV 在轮询），优先消费
  const dKey = `d:${code}`;
  const delivered = await env.DEVICE_KV.get(dKey);
  if (delivered != null) {
    await env.DEVICE_KV.delete(dKey); // 一次性消费
    return json({ status: 'ready', activation: (JSON.parse(delivered) as DeliveredRecord).activation });
  }

  const key = `c:${code}`;
  const raw = await env.DEVICE_KV.get(key);

  // 首次轮询 = 设备登记（submit 只认登记过的短码，挡住逐码盲投）
  if (raw == null) {
    await env.DEVICE_KV.put(key, JSON.stringify({ ts: Date.now() }), {
      expirationTtl: TTL_SECONDS,
    });
    return json({ status: 'waiting' });
  }

  let rec: SessionRecord;
  try {
    rec = JSON.parse(raw) as SessionRecord;
  } catch {
    rec = { ts: Date.now() };
  }

  if (!rec.activation) {
    // 用户还停在解锁卡上等 → 续期，别让短码在等待途中过期
    await env.DEVICE_KV.put(key, JSON.stringify(rec), {
      expirationTtl: TTL_SECONDS,
    });
    return json({ status: 'waiting' });
  }

  await env.DEVICE_KV.delete(key); // 一次性消费
  return json({ status: 'ready', activation: rec.activation });
}

/** 手机端提交激活码到指定短码。 */
async function submit(request: Request, env: Env): Promise<Response> {
  let body: DeviceBody;
  try {
    body = (await request.json()) as DeviceBody;
  } catch {
    return json({ error: 'bad_json' }, 400);
  }

  const code = String(body.code || '').trim().toLowerCase();
  const activation = String(body.activation || '').trim();

  if (!CODE_RE.test(code)) return json({ error: 'bad_code' }, 400);
  if (!activationShapeOk(activation)) return json({ error: 'bad_activation' }, 400);

  // 按 IP 限速（KV 计数器，1 小时窗口；宽松够用，只挡扫号）
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = `r:${ip}`;
  const used = parseInt((await env.DEVICE_KV.get(rlKey)) || '0', 10);
  if (used >= MAX_SUBMITS_PER_HOUR) return json({ error: 'rate_limited' }, 429);
  await env.DEVICE_KV.put(rlKey, String(used + 1), { expirationTtl: 3600 });

  const key = `c:${code}`;
  const raw = await env.DEVICE_KV.get(key);
  // 短码不存在 = 电视没在轮询（过期 / 页面上的短码是旧的）
  if (raw == null) return json({ error: 'code_not_live' }, 409);

  let rec: SessionRecord;
  try {
    rec = JSON.parse(raw) as SessionRecord;
  } catch {
    rec = { ts: Date.now() };
  }
  if (rec.activation) return json({ error: 'already_used' }, 409);

  rec.activation = activation;
  rec.ts = Date.now();
  await env.DEVICE_KV.put(key, JSON.stringify(rec), {
    expirationTtl: TTL_SECONDS,
  });
  return json({ ok: true });
}

/**
 * 发码方一键投递：不要求 TV 正在轮询。
 * - 永远写 d:<短码>（TTL 7 天），TV 哪怕几天后才打开解锁卡也能取到；
 * - TV 恰好在轮询中（c:<短码> 存在且还没有码）时同步写入，3 秒内即达。
 */
async function adminDeliver(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (!checkAdmin(request, url, env)) return json({ error: 'unauthorized' }, 403);

  let body: DeviceBody;
  try {
    body = (await request.json()) as DeviceBody;
  } catch {
    return json({ error: 'bad_json' }, 400);
  }
  const code = String(body.code || '').trim().toLowerCase();
  const activation = String(body.activation || '').trim();
  if (!CODE_RE.test(code)) return json({ error: 'bad_code' }, 400);
  if (!activationShapeOk(activation)) return json({ error: 'bad_activation' }, 400);

  // TV 在线（正在轮询）则同步写 c: 键，下一拍立即取走
  const cKey = `c:${code}`;
  const raw = await env.DEVICE_KV.get(cKey);
  let live = false;
  if (raw != null) {
    let rec: SessionRecord;
    try {
      rec = JSON.parse(raw) as SessionRecord;
    } catch {
      rec = { ts: Date.now() };
    }
    if (!rec.activation) {
      rec.activation = activation;
      rec.ts = Date.now();
      await env.DEVICE_KV.put(cKey, JSON.stringify(rec), { expirationTtl: TTL_SECONDS });
      live = true;
    }
  }

  // d: 键兜底：TV 离线也能投，7 天内开解锁卡即自动消费
  await env.DEVICE_KV.put(
    `d:${code}`,
    JSON.stringify({ activation, ts: Date.now() }),
    { expirationTtl: DELIVERED_TTL_SECONDS },
  );
  return json({ ok: true, live });
}

/** 发码方查投递状态：d: 是否还在等待消费（delivered=false = 电视还没取走）。 */
async function adminStatus(request: Request, url: URL, env: Env): Promise<Response> {
  if (!checkAdmin(request, url, env)) return json({ error: 'unauthorized' }, 403);
  const code = (url.searchParams.get('c') || '').trim().toLowerCase();
  if (!CODE_RE.test(code)) return json({ error: 'bad_code' }, 400);
  const delivered = await env.DEVICE_KV.get(`d:${code}`);
  if (delivered == null) return json({ delivered: false });
  return json({ delivered: true, ts: (JSON.parse(delivered) as DeliveredRecord).ts });
}
