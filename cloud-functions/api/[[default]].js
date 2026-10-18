/**
 * EdgeOne Makers Node Function —— 站点动态能力入口（/api/*）
 *
 * 职责：
 *   1. 签发 Blob 预签名上传 URL（文件字节不经过函数，支持大文件）
 *   2. 上传完成后建立待审记录：成员 → pending，管理员 → 直接发布
 *   3. 管理员审核（通过 / 驳回）
 *   4. 代理读取 setups 分支文件清单，避免浏览器端被 GitHub 限流
 *
 * 依赖环境变量：
 *   JWT_SECRET  —— 与 middleware.js 同一密钥（复用登录态）
 *   GH_TOKEN    —— GitHub fine-grained PAT，需含目标仓库 Contents: Read and write
 *   GH_OWNER / GH_REPO / GH_BRANCH —— 可选，默认 leokkle / mc-resource-nav / setups
 */

import crypto from "node:crypto";

const COOKIE = "mcnav_t";
const STORE_NAME = "mcnav";
const MAX_BYTES = 40 * 1024 * 1024;
const MAX_FILES_IN_LIST = 300;

const ALLOWED_EXT = new Set([
  "zip", "jar", "mcpack", "mcworld", "mca", "litematic", "schematic", "dat", "nbt",
  "7z", "rar", "gz", "tar",
  "exe", "msi", "apk", "dmg",
  "txt", "json", "yml", "yaml", "cfg", "toml", "properties",
  "png", "jpg", "jpeg", "gif", "webp", "svg", "ico",
  "mp3", "ogg", "wav", "mp4",
  "pdf", "glsl", "frag", "vert", "shader", "mcfunction"
]);

/* ---------------- 基础工具 ---------------- */

function json(data, status, extra) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign(
      { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      extra || {}
    )
  });
}

function readCookie(header, name) {
  if (!header) return null;
  const m = new RegExp("(?:^|;\\s*)" + name + "=([^;]+)").exec(header);
  return m ? decodeURIComponent(m[1]) : null;
}

function b64urlToBuffer(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Buffer.from(t, "base64");
}

function verifyJwt(token, secret) {
  if (!token || !secret) return null;
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  const expected = crypto.createHmac("sha256", secret).update(parts[0] + "." + parts[1]).digest();
  const actual = b64urlToBuffer(parts[2]);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;
  let payload;
  try { payload = JSON.parse(b64urlToBuffer(parts[1]).toString("utf8")); } catch (e) { return null; }
  if (!payload || !payload.exp || payload.exp * 1000 < Date.now()) return null;
  return payload;
}

function userOf(request, env) {
  const token = readCookie(request.headers.get("cookie"), COOKIE);
  const payload = verifyJwt(token, env && env.JWT_SECRET);
  if (!payload) return null;
  return {
    role: payload.role === "admin" ? "admin" : "member",
    label: payload.label || (payload.role === "admin" ? "管理员" : "成员")
  };
}

function cleanName(input) {
  let s = String(input || "").replace(/\\/g, "/");
  s = s.split("/").pop() || "";
  s = s.replace(/[\u0000-\u001f<>:"|?*]/g, "").replace(/^\.+/, "").trim();
  if (s.length > 120) {
    const dot = s.lastIndexOf(".");
    const ext = dot > 0 ? s.slice(dot) : "";
    s = s.slice(0, 120 - ext.length) + ext;
  }
  return s;
}

function extOf(name) {
  const m = /\.([A-Za-z0-9]+)$/.exec(name || "");
  return m ? m[1].toLowerCase() : "";
}

function newId() {
  return Date.now().toString(36) + crypto.randomBytes(4).toString("hex");
}

function uniquePath(taken, name) {
  if (!taken.has(name)) return name;
  const dot = name.lastIndexOf(".");
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : "";
  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  let candidate = stem + "-" + stamp + ext;
  let i = 2;
  while (taken.has(candidate)) {
    candidate = stem + "-" + stamp + "-" + i + ext;
    i++;
  }
  return candidate;
}

/* ---------------- Blob 存储 ---------------- */

let storePromise = null;
function getStoreInstance() {
  if (!storePromise) {
    storePromise = import("@edgeone/pages-blob").then(async function (mod) {
      let store = null;
      try { store = await mod.getStore({ name: STORE_NAME, consistency: "strong" }); } catch (e) { store = null; }
      if (!store || typeof store.get !== "function") store = await mod.getStore(STORE_NAME);
      if (!store || typeof store.get !== "function") throw new Error("Blob 存储不可用");
      return store;
    });
  }
  return storePromise;
}

/* ---------------- GitHub ---------------- */

function ghConfig(env) {
  return {
    owner: (env && env.GH_OWNER) || "leokkle",
    repo: (env && env.GH_REPO) || "mc-resource-nav",
    branch: (env && env.GH_BRANCH) || "setups",
    token: (env && env.GH_TOKEN) || ""
  };
}

async function ghFetch(env, method, path, body) {
  const c = ghConfig(env);
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "mcnav-functions"
  };
  if (c.token) headers.Authorization = "Bearer " + c.token;
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch("https://api.github.com" + path, {
    method: method,
    headers: headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text.slice(0, 300) }; }
  return { ok: res.ok, status: res.status, data: data };
}

async function publishToBranch(env, name, buffer) {
  const c = ghConfig(env);
  if (!c.token) throw new Error("GH_TOKEN 未配置");

  const content = Buffer.from(buffer).toString("base64");
  const basePath = "/repos/" + c.owner + "/" + c.repo;
  let lastError = null;

  for (let attempt = 0; attempt < 3; attempt++) {
    const head = await ghFetch(env, "GET", basePath + "/git/ref/heads/" + c.branch);
    if (!head.ok) throw new Error("读取 " + c.branch + " 分支失败（HTTP " + head.status + "）");
    const headSha = head.data.object.sha;

    const commit = await ghFetch(env, "GET", basePath + "/git/commits/" + headSha);
    if (!commit.ok) throw new Error("读取分支提交失败（HTTP " + commit.status + "）");
    const baseTree = commit.data.tree.sha;

    const tree = await ghFetch(env, "GET", basePath + "/git/trees/" + baseTree + "?recursive=1");
    const taken = new Set();
    if (tree.ok && tree.data && Array.isArray(tree.data.tree)) {
      tree.data.tree.forEach(function (node) { taken.add(node.path); });
    }
    const finalPath = uniquePath(taken, name);

    const blob = await ghFetch(env, "POST", basePath + "/git/blobs", { content: content, encoding: "base64" });
    if (!blob.ok) throw new Error("上传文件对象失败（HTTP " + blob.status + "）");

    const newTree = await ghFetch(env, "POST", basePath + "/git/trees", {
      base_tree: baseTree,
      tree: [{ path: finalPath, mode: "100644", type: "blob", sha: blob.data.sha }]
    });
    if (!newTree.ok) throw new Error("构建目录树失败（HTTP " + newTree.status + "）");

    const newCommit = await ghFetch(env, "POST", basePath + "/git/commits", {
      message: "upload: " + finalPath,
      tree: newTree.data.sha,
      parents: [headSha]
    });
    if (!newCommit.ok) throw new Error("创建提交失败（HTTP " + newCommit.status + "）");

    const update = await ghFetch(env, "PATCH", basePath + "/git/refs/heads/" + c.branch, {
      sha: newCommit.data.sha,
      force: false
    });
    if (update.ok) return { path: finalPath, commit: newCommit.data.sha };
    lastError = new Error("更新分支失败（HTTP " + update.status + "）");
  }
  throw lastError || new Error("发布失败");
}

/* ---------------- 业务处理 ---------------- */

async function handleUploadUrl(request, env, user) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ ok: false, error: "bad_body" }, 400); }

  const name = cleanName(body && body.name);
  const size = Number((body && body.size) || 0);
  const type = String((body && body.type) || "application/octet-stream").replace(/[^\w.+\/-]/g, "").slice(0, 100) || "application/octet-stream";

  if (!name) return json({ ok: false, error: "bad_name", message: "文件名不合法" }, 400);
  if (!ALLOWED_EXT.has(extOf(name))) {
    return json({ ok: false, error: "bad_ext", message: "不支持的文件类型：." + extOf(name) }, 400);
  }
  if (!(size > 0) || size > MAX_BYTES) {
    return json({ ok: false, error: "too_large", limit: MAX_BYTES, message: "单文件上限 40 MB" }, 413);
  }

  const store = await getStoreInstance();
  const id = newId();
  const stageKey = "stage/" + id + "/" + name;
  const signed = await store.createUploadUrl(stageKey, { expireSeconds: 1800, contentType: type });

  await store.setJSON("meta/" + id + ".json", {
    id: id,
    name: name,
    size: size,
    type: type,
    note: String((body && body.note) || "").slice(0, 200),
    role: user.role,
    label: user.label,
    status: "uploading",
    stageKey: stageKey,
    createdAt: new Date().toISOString()
  });

  return json({
    ok: true,
    id: id,
    name: name,
    uploadUrl: signed.url,
    contentType: type,
    expiresAt: signed.expiresAt
  });
}

async function handleUploadCommit(request, env, user) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ ok: false, error: "bad_body" }, 400); }
  const id = String((body && body.id) || "").replace(/[^a-z0-9]/gi, "");
  if (!id) return json({ ok: false, error: "bad_id" }, 400);

  const store = await getStoreInstance();
  const meta = await store.get("meta/" + id + ".json", { type: "json", consistency: "strong" });
  if (!meta) return json({ ok: false, error: "record_not_found" }, 404);

  const buffer = await store.get(meta.stageKey, { type: "arrayBuffer", consistency: "strong" });
  if (!buffer || !buffer.byteLength) return json({ ok: false, error: "upload_not_found", message: "没有收到文件内容，请重新上传" }, 409);

  meta.size = buffer.byteLength;
  meta.uploadedAt = new Date().toISOString();

  if (user.role === "admin") {
    try {
      const result = await publishToBranch(env, meta.name, buffer);
      meta.status = "published";
      meta.publishedAs = result.path;
      meta.publishedAt = new Date().toISOString();
      await store.setJSON("meta/" + id + ".json", meta);
      await store.delete(meta.stageKey);
      return json({ ok: true, status: "published", name: result.path, path: result.path });
    } catch (err) {
      meta.status = "pending";
      meta.reviewNote = "管理员直传自动发布失败，已转入待审：" + String(err && err.message || err);
      await store.setJSON("meta/" + id + ".json", meta);
      return json({ ok: true, status: "pending", warning: String(err && err.message || err) }, 202);
    }
  }

  meta.status = "pending";
  await store.setJSON("meta/" + id + ".json", meta);
  return json({ ok: true, status: "pending", message: "已提交，等待管理员审核" });
}

async function handlePending(env, user) {
  const store = await getStoreInstance();
  const listed = await store.list({ prefix: "meta/", consistency: "strong" });
  const keys = (listed && listed.blobs ? listed.blobs : []).map(function (b) { return b.key; }).slice(-MAX_FILES_IN_LIST);

  const items = [];
  for (let i = 0; i < keys.length; i++) {
    const m = await store.get(keys[i], { type: "json", consistency: "strong" });
    if (!m || !m.id) continue;
    if (m.status === "pending" || m.status === "uploading") {
      items.push({
        id: m.id,
        name: m.name,
        size: m.size,
        note: m.note || "",
        role: m.role,
        label: m.label || "",
        status: m.status,
        createdAt: m.createdAt,
        reviewNote: m.reviewNote || ""
      });
    }
  }
  items.sort(function (a, b) { return a.createdAt < b.createdAt ? 1 : -1; });

  if (user.role !== "admin") {
    return json({
      ok: true,
      role: user.role,
      pendingCount: items.filter(function (x) { return x.status === "pending"; }).length,
      items: []
    });
  }
  return json({ ok: true, role: user.role, pendingCount: items.length, items: items });
}

async function handleReview(request, env, user) {
  if (user.role !== "admin") return json({ ok: false, error: "forbidden" }, 403);

  let body;
  try { body = await request.json(); } catch (e) { return json({ ok: false, error: "bad_body" }, 400); }
  const id = String((body && body.id) || "").replace(/[^a-z0-9]/gi, "");
  const action = String((body && body.action) || "");
  if (!id || ["approve", "reject"].indexOf(action) < 0) return json({ ok: false, error: "bad_request" }, 400);

  const store = await getStoreInstance();
  const meta = await store.get("meta/" + id + ".json", { type: "json", consistency: "strong" });
  if (!meta) return json({ ok: false, error: "record_not_found" }, 404);
  if (meta.status !== "pending") return json({ ok: false, error: "not_pending", status: meta.status }, 409);

  meta.reviewedAt = new Date().toISOString();
  meta.reviewer = user.label;

  if (action === "reject") {
    meta.status = "rejected";
    meta.reviewNote = String((body && body.reason) || "").slice(0, 200) || "管理员驳回";
    await store.setJSON("meta/" + id + ".json", meta);
    await store.delete(meta.stageKey);
    return json({ ok: true, status: "rejected" });
  }

  const buffer = await store.get(meta.stageKey, { type: "arrayBuffer", consistency: "strong" });
  if (!buffer || !buffer.byteLength) return json({ ok: false, error: "upload_not_found" }, 409);

  try {
    const result = await publishToBranch(env, meta.name, buffer);
    meta.status = "published";
    meta.publishedAs = result.path;
    meta.publishedAt = new Date().toISOString();
    await store.setJSON("meta/" + id + ".json", meta);
    await store.delete(meta.stageKey);
    return json({ ok: true, status: "published", name: result.path });
  } catch (err) {
    meta.reviewNote = "发布失败：" + String(err && err.message || err);
    await store.setJSON("meta/" + id + ".json", meta);
    return json({ ok: false, error: "publish_failed", message: String(err && err.message || err) }, 502);
  }
}

async function handleSetups(env) {
  const c = ghConfig(env);
  const base = "/repos/" + c.owner + "/" + c.repo;
  const r = await ghFetch(env, "GET", base + "/git/trees/" + c.branch + "?recursive=1");
  if (!r.ok) return json({ ok: false, error: "github_" + r.status }, 502);
  const files = ((r.data && r.data.tree) || [])
    .filter(function (n) { return n.type === "blob"; })
    .map(function (n) { return { path: n.path, size: n.size }; });
  return json({ ok: true, branch: c.branch, files: files });
}

function handleHealth(env) {
  const c = ghConfig(env);
  return json({
    ok: true,
    maxBytes: MAX_BYTES,
    github: { configured: !!c.token, owner: c.owner, repo: c.repo, branch: c.branch },
    jwt: !!(env && env.JWT_SECRET)
  });
}

/* ---------------- 入口 ---------------- */

export default async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = (url.pathname || "/").replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") return new Response(null, { status: 204 });

  try {
    if (path === "/api/health") return handleHealth(env);

    const user = userOf(request, env);
    if (!user) return json({ ok: false, error: "unauthorized", message: "登录状态已失效，请重新登录" }, 401);

    if (path === "/api/upload-url") {
      if (method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
      return await handleUploadUrl(request, env, user);
    }
    if (path === "/api/upload-commit") {
      if (method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
      return await handleUploadCommit(request, env, user);
    }
    if (path === "/api/pending") {
      if (method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
      return await handlePending(env, user);
    }
    if (path === "/api/review") {
      if (method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
      return await handleReview(request, env, user);
    }
    if (path === "/api/setups") {
      if (method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
      return await handleSetups(env);
    }

    return json({ ok: false, error: "not_found", path: path }, 404);
  } catch (err) {
    return json({
      ok: false,
      error: "server_error",
      message: String((err && err.message) || err)
    }, 500);
  }
}
