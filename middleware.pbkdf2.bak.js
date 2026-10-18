// EdgeOne Makers 中间件：全站鉴权 + 登录/登出/会话查询
// 令牌与密钥都不在静态文件里；PBKDF2 校验与 JWT 签发均在边缘节点完成。

const COOKIE = "mcnav_t";
const PBKDF2_ITER = 150000;
const SESSION_HOURS = 12;
const MAX_FAIL = 5;
const LOCK_MS = 60 * 1000;

// PBKDF2-SHA256，150000 轮。哈希不可逆，公开无风险。
const ACCOUNTS = [
  { role: "admin",  label: "管理员", hash: "823ed162da1c2710b3f3667e75b10a7a22e1c5cb62531120e84258f3d669ce81",  salt: "844b082af3a9ec4d8da423315e9ea3c5" },
  { role: "member", label: "成员",   hash: "b12b014294f6c54317ac36411c3ec0ab4c448b174e2d680e0726ff55c01e2fc9", salt: "e8db4f736f854dd20dc50ab844019452" }
];

const PUBLIC_PATHS = ["/login.html", "/favicon.ico", "/robots.txt"];
// /auth/* 由本中间件处理；/api/* 交给 cloud-functions，函数内部各自校验 JWT，
// 未登录时统一返回 401 JSON，而不是 302 到登录页（避免前端 fetch 拿到 HTML）。
const PUBLIC_PREFIX = ["/auth/", "/api/"];

/* ---------- 工具 ---------- */
const enc = new TextEncoder();

function b64url(bytes) {
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlText(text) { return b64url(enc.encode(text)); }

function b64urlDecodeText(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(out);
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
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
async function matchAccount(token) {
  if (!token || token.length > 128) return null;
  for (let i = 0; i < ACCOUNTS.length; i++) {
    const acc = ACCOUNTS[i];
    let digest;
    try {
      const key = await crypto.subtle.importKey(
        "raw", enc.encode(token), { name: "PBKDF2" }, false, ["deriveBits"]
      );
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: hexToBytes(acc.salt), iterations: PBKDF2_ITER, hash: "SHA-256" },
        key, 256
      );
      digest = bytesToHex(bits);
    } catch (e) {
      return null;
    }
    if (safeEqualHex(digest, acc.hash)) return acc;
  }
  return null;
}

/* ---------- JWT ---------- */
async function hmacKey(secret, usage) {
  return crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]
  );
}
async function signJwt(payload, secret) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64urlText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64urlText(JSON.stringify(Object.assign({}, payload, {
    iat: now, exp: now + SESSION_HOURS * 3600
  })));
  const input = head + "." + body;
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret, "sign"), enc.encode(input));
  return input + "." + b64url(sig);
}
async function verifyJwt(token, secret) {
  if (!token || !secret) return null;
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  let header;
  try { header = JSON.parse(b64urlDecodeText(parts[0])); } catch (e) { return null; }
  if (!header || header.alg !== "HS256") return null;
  const sigB64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
  const padded = sigB64 + "=".repeat((4 - (sigB64.length % 4)) % 4);
  const bin = atob(padded);
  const sig = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) sig[i] = bin.charCodeAt(i);
  const ok = await crypto.subtle.verify(
    "HMAC", await hmacKey(secret, "verify"), sig, enc.encode(parts[0] + "." + parts[1])
  );
  if (!ok) return null;
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
  const secret = env && env.JWT_SECRET;

  /* 登录 */
  if (path === "/auth/login") {
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (!secret) return json({ ok: false, error: "server_not_configured" }, 500);

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

    const acc = await matchAccount(token);
    if (!acc) {
      b.n++;
      return json({ ok: false, error: "invalid", left: Math.max(0, MAX_FAIL - b.n) }, 401);
    }
    b.n = 0;
    const jwt = await signJwt({ sub: acc.role, role: acc.role, label: acc.label }, secret);
    return json({ ok: true, role: acc.role, label: acc.label }, 200, {
      "Set-Cookie": COOKIE + "=" + jwt + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + (SESSION_HOURS * 3600)
    });
  }

  /* 会话查询 */
  if (path === "/auth/me") {
    const payload = await verifyJwt(readCookie(request.headers.get("cookie"), COOKIE), secret);
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
  if (!secret) return new Response("Server not configured", { status: 500 });
  const payload = await verifyJwt(readCookie(request.headers.get("cookie"), COOKIE), secret);
  if (!payload) {
    return redirect("/login.html?next=" + encodeURIComponent(path + url.search), 302);
  }
  return next();
}

export const config = { matcher: ["/:path*"] };
