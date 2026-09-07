import crypto from "node:crypto";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SESSION_TTL_DAYS = 30;
const LIMITS = { admin: 5, developer: 2 };

function json(res, status, body) {
  res.status(status).setHeader("Content-Type", "application/json; charset=utf-8").json(body);
}
function ok(res, data = {}) { return json(res, 200, { ok: true, data }); }
function fail(res, status, message) { return json(res, status, { ok: false, message }); }
function rand(n = 20) { return crypto.randomBytes(n).toString("base64url"); }
function uid() { return `USR-${crypto.randomBytes(4).toString("hex").toUpperCase()}`; }
function oid() { return `ORD-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`; }
function normalizeWA(v = "") {
  let n = String(v).replace(/\D/g, "");
  if (n.startsWith("0")) n = "62" + n.slice(1);
  if (n.startsWith("8")) n = "62" + n;
  return n;
}
function isValidWA(v) { return /^62\d{8,15}$/.test(normalizeWA(v)); }
function isValidUsername(v) { return /^[A-Za-z0-9_.-]{3,32}$/.test(String(v || "")); }
function validPassword(v) { return typeof v === "string" && v.length >= 6 && v.length <= 128; }
async function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}
async function sb(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) throw new Error("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum diatur di Vercel.");
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      "Content-Type": "application/json",
      Prefer: options.prefer || "return=representation",
      ...(options.headers || {})
    }
  });
  const text = await r.text();
  let data = [];
  try { data = text ? JSON.parse(text) : []; } catch { data = []; }
  if (!r.ok) throw new Error(data?.message || data?.hint || text || `Supabase ${r.status}`);
  return data;
}
async function one(table, query) { const rows = await sb(`${table}?${query}`); return rows[0] || null; }
function bearer(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : "";
}
async function authUser(req) {
  const token = bearer(req);
  if (!token) throw Object.assign(new Error("Session tidak ditemukan."), { code: 401 });
  const session = await one("sessions", `token=eq.${encodeURIComponent(token)}&select=user_id,expires_at`);
  if (!session || new Date(session.expires_at) < new Date()) throw Object.assign(new Error("Session sudah kedaluwarsa."), { code: 401 });
  const user = await one("users", `user_id=eq.${encodeURIComponent(session.user_id)}&select=*`);
  if (!user || user.status === "blacklisted") throw Object.assign(new Error("Akun tidak tersedia."), { code: 403 });
  return user;
}
function requireRole(user, roles) {
  if (!roles.includes(user.role)) throw Object.assign(new Error("Akses ditolak."), { code: 403 });
}
async function countsByRole(role) {
  const rows = await sb(`users?role=eq.${encodeURIComponent(role)}&select=user_id`);
  return rows.length;
}
async function stateFor(user) {
  const products = await sb("products?active=eq.true&order=created_at.desc&select=*");
  const orders = await sb(`orders?user_id=eq.${encodeURIComponent(user.user_id)}&order=created_at.desc&limit=200&select=*`);
  const allOrders = (user.role === "admin" || user.role === "developer")
    ? await sb("orders?order=created_at.desc&limit=500&select=*")
    : orders;
  const users = user.role === "developer"
    ? await sb("users?order=created_at.desc&limit=500&select=user_id,username,role,status,protected,created_at,updated_at,last_login_at")
    : [];
  const backups = await sb("backups?order=created_at.asc&select=*");
  const roles = await sb("users?role=in.(admin,developer)&select=user_id,username,role,created_at");
  return { user, products, orders: allOrders, users, backups, roles };
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return fail(res, 405, "POST diperlukan.");
    const body = req.body || {};
    const action = String(body.action || "");

    if (action === "register") {
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      if (!isValidUsername(username)) return fail(res, 400, "Username 3–32 karakter dan hanya boleh huruf, angka, titik, underscore, atau minus.");
      if (!validPassword(password)) return fail(res, 400, "Password minimal 6 karakter.");
      const existing = await one("users", `username=ilike.${encodeURIComponent(username)}&select=user_id`);
      if (existing) return fail(res, 409, "Username sudah digunakan.");
      const user = { user_id: uid(), username, password_hash: await hashPassword(password), role: "user", status: "active", protected: false, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), last_login_at: new Date().toISOString() };
      await sb("users", { method: "POST", body: JSON.stringify(user) });
      const token = rand(30);
      const expires = new Date(Date.now() + SESSION_TTL_DAYS*86400000).toISOString();
      await sb("sessions", { method: "POST", body: JSON.stringify({ token, user_id: user.user_id, expires_at: expires, created_at: new Date().toISOString() }) });
      return ok(res, { token, user });
    }

    if (action === "login") {
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      const user = await one("users", `username=ilike.${encodeURIComponent(username)}&select=*`);
      if (!user || user.status === "blacklisted" || !(await hashPassword(password) === user.password_hash)) return fail(res, 401, "Username atau password salah.");
      await sb(`users?user_id=eq.${encodeURIComponent(user.user_id)}`, { method: "PATCH", body: JSON.stringify({ last_login_at: new Date().toISOString(), updated_at: new Date().toISOString() }) });
      const token = rand(30);
      const expires = new Date(Date.now() + SESSION_TTL_DAYS*86400000).toISOString();
      await sb("sessions", { method: "POST", body: JSON.stringify({ token, user_id: user.user_id, expires_at: expires, created_at: new Date().toISOString() }) });
      return ok(res, { token, user });
    }

    if (action === "me") {
      const user = await authUser(req);
      return ok(res, { user });
    }

    if (action === "logout") {
      const token = bearer(req);
      if (token) await sb(`sessions?token=eq.${encodeURIComponent(token)}`, { method: "DELETE", prefer: "return=minimal" });
      return ok(res, {});
    }

    const user = await authUser(req);

    if (action === "state") return ok(res, await stateFor(user));

    if (action === "add_product") {
      requireRole(user, ["developer"]);
      const p = body.product || {};
      if (!p.name || !isValidWA(p.wa) || !p.qris) return fail(res, 400, "Nama, WhatsApp, dan QRIS wajib diisi.");
      const product = { id: `PROD-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`, name: String(p.name).trim(), price: Number(p.price || 0), wa: normalizeWA(p.wa), category: ["TikTok","Instagram","Saluran WhatsApp","Lainnya"].includes(p.category) ? p.category : "Lainnya", description: String(p.description || ""), qris: String(p.qris), stock: "UNLIMITED", active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
      if (product.price < 0) return fail(res, 400, "Harga tidak valid.");
      await sb("products", { method: "POST", body: JSON.stringify(product) });
      return ok(res, await stateFor(user));
    }

    if (action === "delete_product") {
      requireRole(user, ["developer"]);
      await sb(`products?id=eq.${encodeURIComponent(body.productId)}`, { method: "DELETE", prefer: "return=minimal" });
      return ok(res, await stateFor(user));
    }

    if (action === "create_order") {
      const o = body.order || {};
      const p = await one("products", `id=eq.${encodeURIComponent(o.productId)}&active=eq.true&select=*`);
      if (!p) return fail(res, 404, "Produk tidak ditemukan.");
      const quantity = Math.max(1, Math.floor(Number(o.quantity || 1)));
      const order = { id: oid(), product_id: p.id, product_name: p.name, price: Number(p.price), quantity, total: Number(p.price)*quantity, user_id: user.user_id, username: user.username, name: String(o.name || "").trim(), customer_wa: normalizeWA(o.customerWA), target: String(o.target || "").trim(), note: String(o.note || ""), seller_wa: p.wa, qris: p.qris, status: "PENDING", created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
      if (!order.name || !isValidWA(order.customer_wa) || !/^https:\/\/\S+$/i.test(order.target)) return fail(res, 400, "Data order tidak valid.");
      await sb("orders", { method: "POST", body: JSON.stringify(order) });
      return ok(res, { order, orders: (await stateFor(user)).orders });
    }

    if (action === "done_order") {
      requireRole(user, ["admin","developer"]);
      await sb(`orders?id=eq.${encodeURIComponent(body.orderId)}`, { method: "PATCH", body: JSON.stringify({ status: "DONE", processed_by: user.user_id, updated_at: new Date().toISOString() }) });
      return ok(res, await stateFor(user));
    }

    if (action === "add_backup") {
      requireRole(user, ["developer"]);
      if (!isValidWA(body.number)) return fail(res, 400, "Nomor backup tidak valid.");
      const item = { id: `B-${Date.now().toString(36)}`, number: normalizeWA(body.number), label: String(body.label || "Backup"), active: true, created_at: new Date().toISOString() };
      await sb("backups", { method: "POST", body: JSON.stringify(item) });
      return ok(res, await stateFor(user));
    }

    if (action === "toggle_backup") {
      requireRole(user, ["developer"]);
      const item = await one("backups", `id=eq.${encodeURIComponent(body.backupId)}&select=*`);
      if (!item) return fail(res,404,"Nomor backup tidak ditemukan.");
      await sb(`backups?id=eq.${encodeURIComponent(item.id)}`, { method: "PATCH", body: JSON.stringify({ active: !item.active }) });
      return ok(res, await stateFor(user));
    }

    if (action === "remove_backup") {
      requireRole(user, ["developer"]);
      await sb(`backups?id=eq.${encodeURIComponent(body.backupId)}`, { method: "DELETE", prefer: "return=minimal" });
      return ok(res, await stateFor(user));
    }

    if (action === "update_role") {
      requireRole(user, ["developer"]);
      const target = await one("users", `user_id=eq.${encodeURIComponent(body.userId)}&select=*`);
      if (!target || target.protected || target.user_id === user.user_id) return fail(res, 403, "User ini dilindungi.");
      const role = ["user","admin","developer"].includes(body.role) ? body.role : "user";
      if (role === "admin" && await countsByRole("admin") >= LIMITS.admin) return fail(res, 409, "Slot Admin sudah penuh.");
      if (role === "developer" && await countsByRole("developer") >= LIMITS.developer) return fail(res, 409, "Slot Developer sudah penuh.");
      await sb(`users?user_id=eq.${encodeURIComponent(target.user_id)}`, { method: "PATCH", body: JSON.stringify({ role, updated_at: new Date().toISOString() }) });
      return ok(res, await stateFor(user));
    }

    if (action === "blacklist_user") {
      requireRole(user, ["developer"]);
      const target = await one("users", `user_id=eq.${encodeURIComponent(body.userId)}&select=*`);
      if (!target || target.protected || target.user_id === user.user_id) return fail(res,403,"User ini dilindungi.");
      await sb(`users?user_id=eq.${encodeURIComponent(target.user_id)}`, { method: "PATCH", body: JSON.stringify({ status: "blacklisted", updated_at: new Date().toISOString() }) });
      await sb(`sessions?user_id=eq.${encodeURIComponent(target.user_id)}`, { method: "DELETE", prefer: "return=minimal" });
      return ok(res, await stateFor(user));
    }

    if (action === "unblacklist_user") {
      requireRole(user, ["developer"]);
      await sb(`users?user_id=eq.${encodeURIComponent(body.userId)}`, { method: "PATCH", body: JSON.stringify({ status: "active", updated_at: new Date().toISOString() }) });
      return ok(res, await stateFor(user));
    }

    if (action === "delete_user") {
      requireRole(user, ["developer"]);
      const target = await one("users", `user_id=eq.${encodeURIComponent(body.userId)}&select=*`);
      if (!target || target.protected || target.user_id === user.user_id) return fail(res,403,"User ini dilindungi.");
      await sb(`sessions?user_id=eq.${encodeURIComponent(target.user_id)}`, { method: "DELETE", prefer: "return=minimal" });
      await sb(`users?user_id=eq.${encodeURIComponent(target.user_id)}`, { method: "DELETE", prefer: "return=minimal" });
      return ok(res, await stateFor(user));
    }

    return fail(res, 400, "Action tidak dikenali.");
  } catch (error) {
    const code = Number(error.code || 500);
    return fail(res, code, error.message || "Server error.");
  }
}
