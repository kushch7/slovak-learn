import { put, list, del } from "@vercel/blob";
import crypto from "node:crypto";

const SECRET = process.env.SESSION_SECRET || "";
const KEY = crypto.createHash("sha256").update(process.env.DATA_KEY || "").digest();
const LESSONS = Array.from({ length: 60 }, (_, i) => i + 1);

/* ---------- encryption: every stored record is AES-256-GCM encrypted ---------- */
function enc(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const d = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), d]).toString("base64");
}
function dec(s) {
  const b = Buffer.from(s, "base64");
  const c = crypto.createDecipheriv("aes-256-gcm", KEY, b.subarray(0, 12));
  c.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([c.update(b.subarray(28)), c.final()]).toString("utf8"));
}

/* ---------- blob storage: one folder per record, newest blob wins ---------- */
async function listAll(prefix) {
  let out = [], cursor;
  do {
    const r = await list({ prefix, cursor, limit: 1000 });
    out = out.concat(r.blobs);
    cursor = r.hasMore ? r.cursor : undefined;
  } while (cursor);
  return out;
}
const newest = (bl) => bl.slice().sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt))[0];
async function fetchBlob(b) {
  const r = await fetch(b.url, { cache: "no-store" });
  if (!r.ok) throw new Error("blob fetch " + r.status);
  return dec(await r.text());
}
async function readOne(folder) {
  const bl = await listAll(folder);
  return bl.length ? fetchBlob(newest(bl)) : null;
}
async function writeOne(folder, obj) {
  const before = await listAll(folder);
  await put(folder + "d.txt", enc(obj), { access: "public", addRandomSuffix: true, contentType: "text/plain" });
  if (before.length) await del(before.map((b) => b.url));
}
async function removeAll(folder) {
  const bl = await listAll(folder);
  if (bl.length) await del(bl.map((b) => b.url));
}
async function readGroup(prefix) {
  const bl = await listAll(prefix);
  const groups = {};
  for (const b of bl) {
    const id = b.pathname.slice(prefix.length).split("/")[0];
    if (!groups[id] || new Date(b.uploadedAt) > new Date(groups[id].uploadedAt)) groups[id] = b;
  }
  const ids = Object.keys(groups);
  const vals = await Promise.all(ids.map((id) => fetchBlob(groups[id]).catch(() => null)));
  const out = {};
  ids.forEach((id, i) => { if (vals[i]) out[id] = vals[i]; });
  return out;
}
const accPath = (id) => `accounts/${id}/`;
const progPath = (id) => `progress/${id}/`;

/* ---------- passwords & tokens ---------- */
function hashPass(p) {
  const salt = crypto.randomBytes(16);
  return salt.toString("hex") + ":" + crypto.scryptSync(p, salt, 32).toString("hex");
}
function checkPass(p, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [s, h] = stored.split(":");
  const calc = crypto.scryptSync(p, Buffer.from(s, "hex"), 32);
  const want = Buffer.from(h, "hex");
  return want.length === calc.length && crypto.timingSafeEqual(want, calc);
}
const b64u = (s) => Buffer.from(s).toString("base64url");
function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  return body + "." + crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
}
function verify(header) {
  if (!header || !header.startsWith("Bearer ")) return null;
  const [body, sig] = header.slice(7).split(".");
  if (!body || !sig) return null;
  const want = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
const DAY = 86400000;
/* короткий токен лише для відкриття PDF-матеріалів (посилання в новій вкладці) */
const fileToken = (r, id, pv) => sign({ r, id, pv, f: 1, exp: Date.now() + DAY });
function verifyFileToken(t) {
  const [body, sig] = String(t || "").split(".");
  if (!SECRET || !body || !sig) return null;
  const want = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8")); return p.f === 1 && p.exp > Date.now() ? p : null; } catch { return null; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const publicAcc = (a) => ({ id: a.id, name: a.name, login: a.login, createdAt: a.createdAt, note: a.note || "", unlocked: a.unlocked || [1], tcfg: a.tcfg || {}, demo: !!a.demo });
const cleanLessons = (arr) => {
  const list = Array.isArray(arr) ? arr : [];
  const lessons = [...new Set(list.map(Number).filter((n) => LESSONS.includes(n)))].sort((a, b) => a - b);
  const tests = [...new Set(list.filter((x) => typeof x === "string" && /^t\d{1,2}$/.test(x)))].sort();
  return [...lessons, ...tests];
};
const cleanTcfg = (o) => {
  const out = {};
  if (!o || typeof o !== "object") return out;
  for (const [k, v] of Object.entries(o).slice(0, 20)) {
    if (!/^t\d{1,2}$/.test(k) || !v || typeof v !== "object") continue;
    out[k] = { tries: Math.max(0, Math.min(9, Math.round(+v.tries || 0))), min: Math.max(0, Math.min(240, Math.round(+v.min || 0))) };
  }
  return out;
};
const validLogin = (l) => /^[a-z0-9._-]{3,30}$/.test(l);
function cleanProgress(p) {
  p = p && typeof p === "object" ? p : {};
  const out = {
    xp: Math.max(0, Math.min(1e7, Number(p.xp) || 0)),
    days: (Array.isArray(p.days) ? p.days : []).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).slice(-90),
    results: {}, stats: { types: {}, dia: Math.max(0, Number(p.stats && p.stats.dia) || 0) }, mist: {}, updatedAt: Date.now()
  };
  out.tests = {};
  for (const [k, t] of Object.entries((p.tests && typeof p.tests === "object") ? p.tests : {}).slice(0, 20)) {
    if (!/^[a-z0-9-]{2,30}$/.test(k) || !t || !Array.isArray(t.att)) continue;
    out.tests[k] = { open: Math.max(0, Math.min(Date.now() + 86400000, +t.open || 0)), att: t.att.slice(-3).filter((x) => x && typeof x === "object").map((x) => ({
      at: +x.at || Date.now(), d: Math.max(0, Math.min(86400, Math.round(+x.d || 0))), auto: !!x.auto, s: Math.max(0, Math.min(500, +x.s || 0)), n: Math.max(0, Math.min(500, Math.round(+x.n || 0))),
      a: (Array.isArray(x.a) ? x.a : []).slice(0, 200).map((r) => [String(Array.isArray(r) ? r[0] : "").slice(0, 80), Math.max(0, Math.min(1, +(Array.isArray(r) ? r[1] : 0) || 0))])
    })) };
  }
  for (const [k, t] of Object.entries((p.mist && typeof p.mist === "object") ? p.mist : {}).slice(0, 300)) {
    if (/^[a-z0-9-]{2,30}\.\d{1,3}$/.test(k) && Number.isFinite(+t)) out.mist[k] = +t;
  }
  for (const [k, r] of Object.entries(p.results || {}).slice(0, 200)) {
    if (!/^[a-z0-9-]{2,30}$/.test(k) || !r) continue;
    out.results[k] = { best: Math.min(100, Math.max(0, +r.best || 0)), last: Math.min(100, Math.max(0, +r.last || 0)), tries: Math.max(0, +r.tries || 0), at: +r.at || Date.now() };
  }
  for (const [k, t] of Object.entries((p.stats && p.stats.types) || {}).slice(0, 20)) {
    if (/^[a-z]{2,10}$/.test(k) && t) out.stats.types[k] = { c: Math.max(0, +t.c || 0), n: Math.max(0, +t.n || 0) };
  }
  return out;
}
async function teacherConfig() {
  let cfg = await readOne("config/teacher/");
  if (!cfg) {
    cfg = { login: (process.env.TEACHER_LOGIN || "lektor").toLowerCase(), pass: hashPass(process.env.TEACHER_PASSWORD || crypto.randomBytes(24).toString("hex")), v: 1 };
    await writeOne("config/teacher/", cfg);
  }
  return cfg;
}
async function allAccounts() {
  const g = await readGroup("accounts/");
  return Object.values(g);
}
async function findAccount(id) {
  if (!/^s_[a-z0-9]{10}$/.test(String(id || ""))) return null;
  return readOne(accPath(id));
}

/* ---------- handler ---------- */
function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify(obj));
}

export { verifyFileToken, findAccount, teacherConfig };

export default async function handler(req, res) {
  try {
    if (req.method === "GET") {
      const checks = {
        SESSION_SECRET: !!SECRET,
        DATA_KEY: !!process.env.DATA_KEY,
        TEACHER_PASSWORD: !!process.env.TEACHER_PASSWORD,
        BLOB_READ_WRITE_TOKEN: !!process.env.BLOB_READ_WRITE_TOKEN
      };
      let storage = "not tested";
      if (checks.BLOB_READ_WRITE_TOKEN) {
        try { await list({ limit: 1 }); storage = "ok"; } catch (e) { storage = "error: " + String(e && e.message || e).slice(0, 200); }
      }
      return send(res, 200, { server: "ok", checks, storage });
    }
    if (req.method !== "POST") return send(res, 405, { error: "method" });
    if (!SECRET || !process.env.DATA_KEY) return send(res, 500, { error: "config" });
    if (!process.env.BLOB_READ_WRITE_TOKEN) return send(res, 500, { error: "storage" });
    let body = req.body;
    if (typeof body === "string") { try { body = JSON.parse(body || "{}"); } catch { body = {}; } }
    body = body || {};
    const action = body.action;
    const auth = verify(req.headers.authorization);

    if (action === "login") {
      const login = String(body.login || "").trim().toLowerCase(), pass = String(body.pass || "");
      if (body.role === "teacher") {
        const cfg = await teacherConfig();
        if (login !== cfg.login || !checkPass(pass, cfg.pass)) { await sleep(600); return send(res, 401, { error: "bad" }); }
        return send(res, 200, { role: "teacher", login: cfg.login, token: sign({ r: "t", v: cfg.v || 1, exp: Date.now() + 14 * DAY }), ft: fileToken("t", null, cfg.v || 1) });
      }
      const acc = (await allAccounts()).find((a) => a.login === login);
      if (!acc || !checkPass(pass, acc.pass)) { await sleep(600); return send(res, 401, { error: "bad" }); }
      const progress = await readOne(progPath(acc.id));
      return send(res, 200, { role: "student", id: acc.id, name: acc.name, unlocked: acc.unlocked || [1], tcfg: acc.tcfg || {}, progress, token: sign({ r: "s", id: acc.id, pv: acc.pv || 1, exp: Date.now() + 60 * DAY }), ft: fileToken("s", acc.id, acc.pv || 1) });
    }

    if (!auth) return send(res, 401, { error: "auth" });

    /* ----- student ----- */
    if (auth.r === "s") {
      const acc = await findAccount(auth.id);
      if (!acc || (acc.pv || 1) !== auth.pv) return send(res, 401, { error: "auth" });
      if (action === "me") {
        const progress = await readOne(progPath(acc.id));
        return send(res, 200, { role: "student", id: acc.id, name: acc.name, unlocked: acc.unlocked || [1], tcfg: acc.tcfg || {}, progress, ft: fileToken("s", acc.id, acc.pv || 1) });
      }
      if (action === "saveProgress") {
        const data = cleanProgress(body.progress);
        if (JSON.stringify(data).length > 200000) return send(res, 413, { error: "size" });
        await writeOne(progPath(acc.id), data);
        return send(res, 200, { ok: true });
      }
      return send(res, 403, { error: "forbidden" });
    }

    /* ----- teacher ----- */
    if (auth.r !== "t") return send(res, 401, { error: "auth" });
    const cfg = await teacherConfig();
    if ((cfg.v || 1) !== auth.v) return send(res, 401, { error: "auth" });

    if (action === "me") return send(res, 200, { role: "teacher", login: cfg.login, ft: fileToken("t", null, cfg.v || 1) });
    if (action === "teacherLoad") {
      const [accs, prog] = await Promise.all([allAccounts(), readGroup("progress/")]);
      return send(res, 200, { accounts: accs.map(publicAcc), progress: prog });
    }
    if (action === "createStudent") {
      const name = String(body.name || "").trim().slice(0, 80), login = String(body.login || "").trim().toLowerCase(), pass = String(body.pass || "");
      if (!name || !validLogin(login) || pass.length < 6) return send(res, 400, { error: "invalid" });
      const accs = await allAccounts();
      if (login === cfg.login || accs.some((a) => a.login === login)) return send(res, 409, { error: "exists" });
      const id = "s_" + Array.from(crypto.randomBytes(10)).map((b) => "abcdefghijkmnpqrstuvwxyz23456789"[b % 32]).join("");
      const acc = { id, name, login, pass: hashPass(pass), pv: 1, createdAt: Date.now(), note: "", unlocked: [] };
      await writeOne(accPath(id), acc);
      return send(res, 200, { account: publicAcc(acc) });
    }
    const acc = body.id ? await findAccount(body.id) : null;
    if (action === "resetPassword") {
      if (!acc || String(body.pass || "").length < 6) return send(res, 400, { error: "invalid" });
      acc.pass = hashPass(String(body.pass)); acc.pv = (acc.pv || 1) + 1;
      await writeOne(accPath(acc.id), acc);
      return send(res, 200, { ok: true });
    }
    if (action === "deleteStudent") {
      if (!acc) return send(res, 404, { error: "notfound" });
      await Promise.all([removeAll(accPath(acc.id)), removeAll(progPath(acc.id))]);
      return send(res, 200, { ok: true });
    }
    if (action === "setTestCfg") {
      if (!acc) return send(res, 404, { error: "notfound" });
      acc.tcfg = cleanTcfg(body.tcfg);
      await writeOne(accPath(acc.id), acc);
      return send(res, 200, { ok: true, tcfg: acc.tcfg });
    }
    if (action === "saveNote") {
      if (!acc) return send(res, 404, { error: "notfound" });
      acc.note = String(body.note || "").slice(0, 4000);
      await writeOne(accPath(acc.id), acc);
      return send(res, 200, { ok: true });
    }
    if (action === "setUnlocked") {
      if (!acc) return send(res, 404, { error: "notfound" });
      acc.unlocked = cleanLessons(body.lessons);
      await writeOne(accPath(acc.id), acc);
      return send(res, 200, { ok: true, unlocked: acc.unlocked });
    }
    if (action === "changeTeacher") {
      const login = String(body.login || "").trim().toLowerCase(), pass = String(body.pass || "");
      if (!validLogin(login) || pass.length < 8) return send(res, 400, { error: "invalid" });
      const next = { login, pass: hashPass(pass), v: (cfg.v || 1) + 1 };
      await writeOne("config/teacher/", next);
      return send(res, 200, { role: "teacher", login, token: sign({ r: "t", v: next.v, exp: Date.now() + 14 * DAY }), ft: fileToken("t", null, next.v) });
    }
    return send(res, 400, { error: "unknown" });
  } catch (e) {
    console.error(e);
    const msg = String(e && e.message || e);
    return send(res, 500, { error: /blob|token|store/i.test(msg) ? "storage" : "server", detail: msg.slice(0, 200) });
  }
}
