// EdgeOne Makers 中间件：全站鉴权 + 登录/登出/会话查询
// v2：移除 EdgeOne 边缘不可靠的 crypto.subtle PBKDF2，改用内置纯 JS SHA-256 / HMAC-SHA256。
// 令牌与密钥都不在静态文件里；比对与 JWT 签发均在边缘节点完成。

const COOKIE = "mcnav_t";
const SESSION_HOURS = 12;
const MAX_FAIL = 5;
const LOCK_MS = 60 * 1000;

// 令牌校验：sig = SHA256(PEPPER + ":" + salt + ":" + token)
// 单次哈希即可，无迭代依赖；令牌本身为 16 位高熵串，暴力穷举不可行。
const PEPPER = "f3b1a9d47c2e6085b7d4e1a95c3f8027d6b9e4a1c7583029fe6b4d2a91c78035";
const ACCOUNTS = [
  { role: "admin",  label: "管理员", salt: "844b082af3a9ec4d8da423315e9ea3c5", sig: "c8ca6f4f85061254e7d232d7bdfe4b5b144a32b808de580846c66ed5ebc8b14e" },
  { role: "member", label: "成员",   salt: "e8db4f736f854dd20dc50ab844019452", sig: "34623ca9f31cf85ed84871b4711889f5071d41f145cd4481bc75c3aa5c598738" }
];

// 环境变量缺失时的兜底密钥，避免因漏配导致全站 500
const DEFAULT_JWT_SECRET = "49fea852acd016e66bb1a4447eee74fbe44caa42d48e379a8eb021795ef43ab4";

const PUBLIC_PATHS = ["/login.html", "/favicon.ico", "/robots.txt"];
// /auth/* 由本中间件处理；/api/* 交给 cloud-functions，函数内部各自校验 JWT
const PUBLIC_PREFIX = ["/auth/", "/api/"];

/* ---------- 纯 JS SHA-256 ---------- */
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function utf8Bytes(text) {
  const s = String(text);
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(s);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
    else if (c < 0xd800 || c >= 0xe000) { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
    else {
      const c2 = s.charCodeAt(++i);
      const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    }
  }
  return new Uint8Array(out);
}

function sha256Bytes(msg) {
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const len = msg.length;
  const total = (((len + 9) + 63) >> 6) << 6;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  const bitLen = len * 8;
  dv.setUint32(total - 8, Math.floor(bitLen / 4294967296), false);
  dv.setUint32(total - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2];
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
  return out;
}

function bytesToHex(buf) {
  const arr = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += (arr[i] < 16 ? "0" : "") + arr[i].toString(16);
  return s;
}

function sha256Hex(text) { return bytesToHex(sha256Bytes(utf8Bytes(text))); }

function hmacSha256Bytes(keyBytes, msgBytes) {
  let key = keyBytes;
  if (key.length > 64) key = sha256Bytes(key);
  const ipad = new Uint8Array(64 + msgBytes.length);
  const opad = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    const k = i < key.length ? key[i] : 0;
    ipad[i] = k ^ 0x36;
    opad[i] = k ^ 0x5c;
  }
  ipad.set(msgBytes, 64);
  opad.set(sha256Bytes(ipad), 64);
  return sha256Bytes(opad);
}

function hmacSha256Hex(key, text) {
  return bytesToHex(hmacSha256Bytes(utf8Bytes(key), utf8Bytes(text)));
}

/* ---------- 编码 / 工具 ---------- */
function b64url(bytes) {
  const arr = new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlText(text) { return b64url(utf8Bytes(text)); }

function b64urlDecodeText(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (typeof TextDecoder !== "undefined") return new TextDecoder().decode(out);
  let res = "";
  for (let i = 0; i < out.length; i++) res += String.fromCharCode(out[i]);
  try { return decodeURIComponent(escape(res)); } catch (e) { return res; }
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function readCookie(header, name) {
  if (!header) return null;
  const m = new RegExp("(?:^|;\\s*)" + name + "=([^;]+)").exec(header);
  return m ? decodeURIComponent(m[1]) : null;
}

function json(data, status, extra) {
  const headers = Object.assign({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  }, extra || {});
  return new Response(JSON.stringify(data), { status: status || 200, headers: headers });
}

/* ---------- 令牌校验 ---------- */
function matchAccount(token) {
  if (!token || token.length > 128) return null;
  for (let i = 0; i < ACCOUNTS.length; i++) {
    const acc = ACCOUNTS[i];
    const sig = sha256Hex(PEPPER + ":" + acc.salt + ":" + token);
    if (safeEqualHex(sig, acc.sig)) return acc;
  }
  return null;
}

/* ---------- JWT（HS256，纯 JS） ---------- */
function signJwt(payload, secret) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64urlText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64urlText(JSON.stringify(Object.assign({}, payload, {
    iat: now, exp: now + SESSION_HOURS * 3600
  })));
  const input = head + "." + body;
  return input + "." + b64url(hmacSha256Bytes(utf8Bytes(secret), utf8Bytes(input)));
}

function verifyJwt(token, secret) {
  if (!token || !secret) return null;
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  let header;
  try { header = JSON.parse(b64urlDecodeText(parts[0])); } catch (e) { return null; }
  if (!header || header.alg !== "HS256") return null;
  const expect = hmacSha256Hex(secret, parts[0] + "." + parts[1]);
  const got = bytesToHex((function () {
    let s = parts[2].replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  })());
  if (!safeEqualHex(expect, got)) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecodeText(parts[1])); } catch (e) { return null; }
  if (!payload || !payload.exp || payload.exp * 1000 < Date.now()) return null;
  return payload;
}

/* ---------- 失败计数（边缘实例级） ---------- */
const fails = new Map();
function failBucket(ip) {
  const now = Date.now();
  let b = fails.get(ip);
  if (!b || b.reset < now) { b = { n: 0, reset: now + LOCK_MS }; fails.set(ip, b); }
  return b;
}

/* ---------- 中间件 ---------- */
export async function middleware(context) {
  const { request, next, redirect, env, clientIp } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const secret = (env && env.JWT_SECRET) || DEFAULT_JWT_SECRET;

  /* 运行时自检：确认边缘节点能算出正确 SHA-256 */
  if (path === "/auth/diag") {
    const probe = sha256Hex("abc");
    return json({
      ok: probe === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      probe: probe,
      hasSubtle: typeof crypto !== "undefined" && !!crypto.subtle,
      hasEncoder: typeof TextEncoder !== "undefined",
      hasBtoa: typeof btoa !== "undefined",
      secretFromEnv: !!(env && env.JWT_SECRET),
      algo: "sha256-pure-js"
    }, 200);
  }

  /* 登录 */
  if (path === "/auth/login") {
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);

    const ip = clientIp || request.headers.get("x-forwarded-for") || "unknown";
    const b = failBucket(ip);
    if (b.n >= MAX_FAIL) {
      return json({ ok: false, error: "locked", retryAfter: Math.ceil((b.reset - Date.now()) / 1000) }, 429);
    }

    let token = "";
    try {
      const ct = request.headers.get("content-type") || "";
      if (ct.indexOf("application/json") >= 0) {
        const body = await request.json();
        token = (body && body.token) || "";
      } else {
        const fd = await request.formData();
        token = fd.get("token") || "";
      }
    } catch (e) {
      return json({ ok: false, error: "bad_request" }, 400);
    }
    token = String(token).trim();
    if (!token) return json({ ok: false, error: "empty" }, 400);

    let acc = null;
    try {
      acc = matchAccount(token);
    } catch (e) {
      return json({ ok: false, error: "verify_failed", detail: String(e && e.message || e).slice(0, 120) }, 500);
    }
    if (!acc) {
      b.n++;
      return json({ ok: false, error: "invalid", left: Math.max(0, MAX_FAIL - b.n) }, 401);
    }
    b.n = 0;
    const jwt = signJwt({ sub: acc.role, role: acc.role, label: acc.label }, secret);
    return json({ ok: true, role: acc.role, label: acc.label }, 200, {
      "Set-Cookie": COOKIE + "=" + jwt + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + (SESSION_HOURS * 3600)
    });
  }

  /* 会话查询 */
  if (path === "/auth/me") {
    const payload = verifyJwt(readCookie(request.headers.get("cookie"), COOKIE), secret);
    if (!payload) return json({ ok: false }, 401);
    return json({ ok: true, role: payload.role, label: payload.label, exp: payload.exp }, 200);
  }

  /* 登出 */
  if (path === "/auth/logout") {
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/login.html",
        "Set-Cookie": COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        "Cache-Control": "no-store"
      }
    });
  }

  /* 函数源码目录不对外暴露 */
  if (path.indexOf("/cloud-functions") === 0) return new Response("Not Found", { status: 404 });

  /* 公开页 */
  if (PUBLIC_PATHS.indexOf(path) >= 0) return next();
  for (let i = 0; i < PUBLIC_PREFIX.length; i++) {
    if (path.indexOf(PUBLIC_PREFIX[i]) === 0) return next();
  }

  /* 全站鉴权 */
  const payload = verifyJwt(readCookie(request.headers.get("cookie"), COOKIE), secret);
  if (!payload) {
    return redirect("/login.html?next=" + encodeURIComponent(path + url.search), 302);
  }
  return next();
}

export const config = { matcher: ["/:path*"] };
