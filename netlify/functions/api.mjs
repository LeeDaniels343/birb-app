// BIRB accounts and bird data: one small API on Netlify Functions, stored in Netlify Blobs.
// Passcodes are salted and hashed with scrypt; sessions are signed tokens; uploads are cleaned of home addresses.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import towns from "./towns.mjs";

export const config = { path: "/api/*" };

const envRaw = (k) => (globalThis.Netlify ? Netlify.env.get(k) : process.env[k]) || "";
const store = () => globalThis.__BIRB_TEST_STORE__ || getStore({ name: "birb", consistency: "strong" });

/* settings: site environment variables win; otherwise they live in private storage. The first invite code is only
   stored here as a fingerprint, so it can't be read from the public code. Lee can change it from the admin screen. */
const DEFAULTS = { ADMIN_USER: "lee", INVITE_HASH: "7f3c8c3e84baaca51281a2a418154db18636fe115d68b38ed4c65149f0d85fa8" };
let cfg = null;
async function settings() {
  let c = (await store().get("config/settings", { type: "json" })) || {};
  if (!c.SESSION_SECRET) { c.SESSION_SECRET = crypto.randomBytes(48).toString("base64url"); await store().setJSON("config/settings", c); }
  cfg = c; return c;
}
const env = (k) => envRaw(k) || (cfg && cfg[k]) || DEFAULTS[k] || "";
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
function inviteOk(code) {
  const c = String(code || "").trim().toUpperCase();
  if (!c) return false;
  if (envRaw("INVITE_CODE")) return c === envRaw("INVITE_CODE").toUpperCase();
  if (cfg && cfg.INVITE_CODE) return c === cfg.INVITE_CODE.toUpperCase();
  return sha(c) === DEFAULTS.INVITE_HASH;
}

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
const fail = (status, message) => json({ error: message }, status);

/* ---------- passcodes and sessions ---------- */
const hashPass = (pass, salt) => crypto.scryptSync(pass, salt, 32, { N: 16384, r: 8, p: 1 }).toString("base64");
const b64u = (buf) => Buffer.from(buf).toString("base64url");
function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", env("SESSION_SECRET")).update(body).digest("base64url");
  return `${body}.${mac}`;
}
function verify(token) {
  if (!token || !env("SESSION_SECRET")) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const want = crypto.createHmac("sha256", env("SESSION_SECRET")).update(body).digest("base64url");
  if (want.length !== mac.length || !crypto.timingSafeEqual(Buffer.from(want), Buffer.from(mac))) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}
const SESSION_DAYS = 180;
const tokenFor = (user) => sign({ u: user.u, v: user.v || 1, exp: Date.now() + SESSION_DAYS * 864e5 });

/* ---------- users ---------- */
const USERNAME = /^[a-z0-9_-]{2,20}$/;
const RESERVED = new Set(["admin", "api", "birb", "root", "flock", "me", "null", "undefined", "everyone", "all"]);
const getUser = async (u) => (u && USERNAME.test(u) ? store().get(`users/${u}`, { type: "json" }) : null);
const putUser = (user) => store().setJSON(`users/${user.u}`, user);
const isAdmin = (u) => !!u && u === env("ADMIN_USER").toLowerCase();

/* a renamed account leaves a pointer behind, so old links and signed-in devices keep working */
async function findUser(u) {
  const user = await getUser(u);
  if (user) return user;
  if (!u || !USERNAME.test(u)) return null;
  const to = await store().get(`aliases/${u}`, { type: "text" });
  return to ? getUser(to) : null;
}
async function sessionUser(req) {
  const auth = req.headers.get("authorization") || "";
  const p = verify(auth.replace(/^Bearer\s+/i, ""));
  if (!p) return null;
  const user = await findUser(p.u);
  return user && (user.v || 1) === p.v ? user : null;
}

const AVATAR_KEYS = new Set(["head", "beak", "wing", "legs", "tail", "eyes", "cHead", "cBody", "cWing", "cBelly", "extra", "bg"]);
function cleanAvatar(a) {
  if (!a || typeof a !== "object") return null;
  const out = {};
  for (const [k, v] of Object.entries(a)) if (AVATAR_KEYS.has(k) && typeof v === "string" && v.length <= 24 && /^[#\w ]+$/.test(v)) out[k] = v;
  return out;
}
const VIS = new Set(["public", "group", "private"]);
const cleanFav = (f) => (f && typeof f === "object" && typeof f.name === "string" && f.name.length <= 80 ? { name: f.name.slice(0, 80), sci: String(f.sci || "").slice(0, 80) } : null);
const publicMe = (user) => ({
  u: user.u, name: user.name || user.u, avatar: user.avatar || null, visibility: user.visibility || "group",
  admin: isAdmin(user.u), birds: user.birds || null, joined: user.joined, mustChange: !!user.mustChange, favourite: user.favourite || null,
});
const card = (user) => ({ u: user.u, name: user.name || user.u, avatar: user.avatar || null, visibility: user.visibility || "group", birds: user.birds || null, owner: isAdmin(user.u), favourite: user.favourite || null });
const canSee = (owner, viewer) => {
  const vis = owner.visibility || "group";
  if (viewer && viewer.u === owner.u) return true;
  if (vis === "public") return true;
  if (vis === "group") return !!viewer;
  return false;
};

/* ---------- CSV clean-up ---------- */
function parseCSV(text) {
  const rows = []; let row = [], f = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(f); f = ""; }
    else if (c === "\n") { row.push(f); rows.push(row); row = []; f = ""; }
    else if (c !== "\r") f += c;
  }
  if (f !== "" || row.length) { row.push(f); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim() !== ""));
}
const cell = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
const KEEP = ["Submission ID", "Common Name", "Scientific Name", "Taxonomic Order", "Count", "State/Province", "County", "Location ID", "Location", "Latitude", "Longitude", "Date", "Time", "Protocol", "Duration (Min)", "Number of Observers"];
const ROAD = /^\s*\d+[a-z]?\s|\b(road|street|lane|avenue|close|drive|crescent|terrace|gardens|grove|court|cottages?|farm|house|mews|place|row|walk|way|home)\b/i;
function nearestTown(lng, lat) {
  let best = null, bd = Infinity;
  const k = Math.cos((lat * Math.PI) / 180);
  for (const [name, x, y] of towns) { const d = ((x - lng) * k) ** 2 + (y - lat) ** 2; if (d < bd) { bd = d; best = name; } }
  return bd < 0.25 ? best : null;
}
/* keeps only the columns the app uses; places that look like a home get an area name, a ~1 km position and no checklist link */
function cleanCSV(text) {
  const rows = parseCSV(text.replace(/^﻿/, ""));
  if (rows.length < 2) throw new Error("The file is empty.");
  const head = rows[0].map((h) => h.trim());
  const ix = Object.fromEntries(head.map((h, i) => [h, i]));
  for (const need of ["Common Name", "Latitude", "Longitude", "Date"]) if (!(need in ix)) throw new Error("This doesn't look like an eBird 'Download My Data' export.");
  const cols = KEEP.filter((h) => h in ix);
  const priv = new Map(), species = new Set(), places = new Set();
  let first = "", last = "";
  const out = [cols.join(",")];
  for (const r of rows.slice(1)) {
    const get = (h) => (ix[h] != null ? (r[ix[h]] || "").trim() : "");
    const lat = parseFloat(get("Latitude")), lng = parseFloat(get("Longitude"));
    if (!get("Common Name") || !isFinite(lat) || !isFinite(lng)) continue;
    const rec = Object.fromEntries(cols.map((h) => [h, get(h)]));
    if (ROAD.test(rec.Location || "")) {
      if (!priv.has(rec.Location)) {
        const t = nearestTown(lng, lat);
        priv.set(rec.Location, { name: t ? `Near ${t}` : "A private spot", lat: lat.toFixed(2), lng: lng.toFixed(2), id: "P" + crypto.createHash("sha1").update(rec.Location).digest("hex").slice(0, 8) });
      }
      const p = priv.get(rec.Location);
      rec.Location = p.name; rec.Latitude = p.lat; rec.Longitude = p.lng; rec["Submission ID"] = "";
      if ("Location ID" in rec) rec["Location ID"] = p.id;
    }
    species.add(rec["Common Name"]); places.add(rec["Location ID"] || rec.Location);
    const d = rec.Date; if (d && (!first || d < first)) first = d; if (d && d > last) last = d;
    out.push(cols.map((h) => cell(rec[h])).join(","));
  }
  if (out.length < 2) throw new Error("No sightings with coordinates were found in this file.");
  return { csv: out.join("\n"), stats: { species: species.size, rows: out.length - 1, places: places.size, first, last, privatePlaces: priv.size } };
}

/* the app gzips uploads; some hosts unpack them on the way in, so look at the bytes, not the header */
/* merge a newly cleaned upload into what's already stored: same sighting = same key, so only new ones are added */
function rowKey(r) {
  const sub = r["Submission ID"], name = r["Common Name"];
  return sub ? `${sub}|${name}` : `${r["Location ID"] || r.Location}|${r.Date}|${r.Time || ""}|${name}`;
}
function toObjs(csv) {
  const rows = parseCSV(csv); if (!rows.length) return { head: [], objs: [] };
  const head = rows[0];
  return { head, objs: rows.slice(1).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] || ""]))) };
}
function statsOf(objs, privatePlaces = 0) {
  const species = new Set(), places = new Set(); let first = "", last = "";
  for (const r of objs) { species.add(r["Common Name"]); places.add(r["Location ID"] || r.Location); const d = r.Date; if (d && (!first || d < first)) first = d; if (d && d > last) last = d; }
  return { species: species.size, rows: objs.length, places: places.size, first, last, privatePlaces };
}
function mergeCSV(oldCsv, newCsv, privatePlaces) {
  const a = toObjs(oldCsv), b = toObjs(newCsv);
  const head = [...b.head, ...a.head.filter((h) => !b.head.includes(h))];
  const map = new Map();
  for (const r of a.objs) map.set(rowKey(r), r);
  const before = new Set(a.objs.map((r) => r["Common Name"]));
  let added = 0; const newSpecies = new Set();
  for (const r of b.objs) { const k = rowKey(r); if (!map.has(k)) { added++; if (!before.has(r["Common Name"])) newSpecies.add(r["Common Name"]); } map.set(k, r); }
  const objs = [...map.values()].sort((x, y) => (x.Date < y.Date ? -1 : x.Date > y.Date ? 1 : 0));
  const csv = [head.join(","), ...objs.map((r) => head.map((h) => cell(r[h] || "")).join(","))].join("\n");
  return { csv, stats: { ...statsOf(objs, privatePlaces), added, newSpecies: [...newSpecies] } };
}

async function readBody(req) {
  const buf = new Uint8Array(await req.arrayBuffer());
  if (buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    const ds = new Blob([buf]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(ds).text();
  }
  return new TextDecoder("utf-8").decode(buf);
}
const jsonBody = async (req) => { try { return await req.json(); } catch { return {}; } };

/* ---------- routes ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const m = req.method;
  try {
    await settings();

    if (path === "join" && m === "POST") {
      const b = await jsonBody(req);
      const u = String(b.username || "").trim().toLowerCase();
      if (!inviteOk(b.invite)) return fail(403, "That invite code isn't right. Check it with Lee.");
      if (!USERNAME.test(u) || RESERVED.has(u)) return fail(400, "Usernames are 2 to 20 letters, numbers, - or _.");
      if (String(b.passcode || "").length < 6) return fail(400, "Passcodes need at least 6 characters.");
      if (await getUser(u)) return fail(409, "That username is taken. Try another.");
      const salt = crypto.randomBytes(16).toString("base64");
      const user = { u, name: String(b.name || u).slice(0, 40), salt, hash: hashPass(String(b.passcode), salt), v: 1, joined: new Date().toISOString(), visibility: isAdmin(u) ? "public" : "group", avatar: cleanAvatar(b.avatar), fails: 0, lockUntil: 0 };
      await putUser(user);
      await store().delete(`aliases/${u}`);
      return json({ token: tokenFor(user), me: publicMe(user) }, 201);
    }

    if (path === "login" && m === "POST") {
      const b = await jsonBody(req);
      const user = await findUser(String(b.username || "").trim().toLowerCase());
      if (!user) return fail(401, "That username and passcode don't match.");
      if (user.lockUntil > Date.now()) return fail(429, `Too many wrong tries. Try again in ${Math.ceil((user.lockUntil - Date.now()) / 60000)} minutes.`);
      if (hashPass(String(b.passcode || ""), user.salt) !== user.hash) {
        user.fails = (user.fails || 0) + 1;
        if (user.fails >= 5) { user.lockUntil = Date.now() + 15 * 60000; user.fails = 0; }
        await putUser(user);
        return fail(401, "That username and passcode don't match.");
      }
      user.fails = 0; user.lockUntil = 0; await putUser(user);
      return json({ token: tokenFor(user), me: publicMe(user) });
    }

    const me = await sessionUser(req);

    if (path === "me") {
      if (!me) return fail(401, "Please sign in.");
      if (m === "GET") return json({ me: publicMe(me) });
      if (m === "PUT") {
        const b = await jsonBody(req);
        if (b.name != null) me.name = String(b.name).trim().slice(0, 40) || me.u;
        if (b.avatar != null) me.avatar = cleanAvatar(b.avatar);
        if (b.visibility != null && VIS.has(b.visibility)) me.visibility = b.visibility;
        if (b.favourite !== undefined) me.favourite = cleanFav(b.favourite);
        await putUser(me);
        return json({ me: publicMe(me) });
      }
    }

    if (path === "username" && m === "POST") {
      if (!me) return fail(401, "Please sign in.");
      const b = await jsonBody(req);
      const nu = String(b.username || "").trim().toLowerCase();
      if (nu === me.u) return json({ token: tokenFor(me), me: publicMe(me) });
      if (!USERNAME.test(nu) || RESERVED.has(nu)) return fail(400, "Usernames are 2 to 20 letters, numbers, - or _.");
      if (await getUser(nu)) return fail(409, "That username is taken. Try another.");
      const taken = await store().get(`aliases/${nu}`, { type: "text" });
      if (taken && taken !== me.u) return fail(409, "That username is taken. Try another.");
      const old = me.u, wasAdmin = isAdmin(old);
      const csv = await store().get(`csv/${old}`, { type: "text" });
      me.u = nu; me.v = me.v || 1;
      await putUser(me);
      if (csv) await store().set(`csv/${nu}`, csv);
      if (wasAdmin) { cfg.ADMIN_USER = nu; await store().setJSON("config/settings", cfg); }
      await store().set(`aliases/${old}`, nu);
      await store().delete(`aliases/${nu}`);
      const { blobs } = await store().list({ prefix: "aliases/" });
      await Promise.all(blobs.map(async (a) => { if ((await store().get(a.key, { type: "text" })) === old) await store().set(a.key, nu); }));
      await store().delete(`csv/${old}`); await store().delete(`users/${old}`);
      return json({ token: tokenFor(me), me: publicMe(me) });
    }

    if (path === "passcode" && m === "POST") {
      if (!me) return fail(401, "Please sign in.");
      const b = await jsonBody(req);
      if (hashPass(String(b.old || ""), me.salt) !== me.hash) return fail(401, "Your current passcode isn't right.");
      if (String(b.passcode || "").length < 6) return fail(400, "Passcodes need at least 6 characters.");
      me.salt = crypto.randomBytes(16).toString("base64"); me.hash = hashPass(String(b.passcode), me.salt); me.v = (me.v || 1) + 1; me.mustChange = false;
      await putUser(me);
      return json({ token: tokenFor(me), me: publicMe(me) });
    }

    if (path === "birds") {
      if (m === "GET") {
        const owner = await findUser(String(url.searchParams.get("u") || "").toLowerCase());
        if (!owner || !owner.birds) return fail(404, "No birds uploaded yet.");
        if (!canSee(owner, me)) return fail(403, owner.visibility === "private" ? "These birds are private." : "Sign in to see these birds.");
        const csv = await store().get(`csv/${owner.u}`, { type: "text" });
        if (!csv) return fail(404, "No birds uploaded yet.");
        return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "cache-control": "no-store" } });
      }
      if (!me) return fail(401, "Please sign in.");
      if (m === "POST") {
        const text = await readBody(req);
        if (text.length > 60e6) return fail(413, "That file is too big.");
        let res;
        try { res = cleanCSV(text); } catch (e) { return fail(400, e.message); }
        const old = url.searchParams.get("mode") === "replace" ? null : await store().get(`csv/${me.u}`, { type: "text" });
        if (old) res = mergeCSV(old, res.csv, res.stats.privatePlaces);
        else res.stats = { ...res.stats, added: res.stats.rows, newSpecies: [], replaced: true };
        await store().set(`csv/${me.u}`, res.csv);
        me.birds = { ...res.stats, updated: new Date().toISOString() };
        await putUser(me);
        return json({ me: publicMe(me), stats: res.stats });
      }
      if (m === "DELETE") {
        await store().delete(`csv/${me.u}`);
        me.birds = null; await putUser(me);
        return json({ me: publicMe(me) });
      }
    }

    if (path === "flock" && m === "GET") {
      const { blobs } = await store().list({ prefix: "users/" });
      const users = (await Promise.all(blobs.map((b) => store().get(b.key, { type: "json" })))).filter(Boolean);
      const members = users.filter((x) => canSee(x, me) || (me && (x.visibility || "group") !== "private")).map(card);
      members.sort((a, b) => (b.owner - a.owner) || ((b.birds?.species || 0) - (a.birds?.species || 0)));
      return json({ owner: env("ADMIN_USER").toLowerCase() || null, me: me ? publicMe(me) : null, members });
    }

    if (path.startsWith("admin/")) {
      if (!me || !isAdmin(me.u)) return fail(404, "Not found.");
      if (path === "admin/users" && m === "GET") {
        const { blobs } = await store().list({ prefix: "users/" });
        const users = (await Promise.all(blobs.map((b) => store().get(b.key, { type: "json" })))).filter(Boolean);
        return json({ users: users.map((x) => ({ ...card(x), joined: x.joined, locked: x.lockUntil > Date.now() })), invite: envRaw("INVITE_CODE") || cfg.INVITE_CODE || "" });
      }
      if (path === "admin/invite" && m === "POST") {
        const b = await jsonBody(req);
        const code = String(b.code || "").trim().toUpperCase();
        if (!/^[A-Z0-9-]{6,32}$/.test(code)) return fail(400, "Invite codes are 6 to 32 letters, numbers or dashes.");
        cfg.INVITE_CODE = code; await store().setJSON("config/settings", cfg);
        return json({ invite: code });
      }
      const b = m === "POST" ? await jsonBody(req) : {};
      const target = await getUser(String(b.u || "").toLowerCase());
      if (!target) return fail(404, "No such member.");
      if (path === "admin/reset" && m === "POST") {
        const temp = crypto.randomBytes(5).toString("base64url").replace(/[-_]/g, "x").slice(0, 7);
        target.salt = crypto.randomBytes(16).toString("base64"); target.hash = hashPass(temp, target.salt);
        target.v = (target.v || 1) + 1; target.fails = 0; target.lockUntil = 0; target.mustChange = true;
        await putUser(target);
        return json({ u: target.u, temp });
      }
      if (path === "admin/remove" && m === "POST") {
        if (target.u === me.u) return fail(400, "You can't remove yourself.");
        await store().delete(`csv/${target.u}`); await store().delete(`users/${target.u}`);
        return json({ removed: target.u });
      }
    }
    return fail(404, "Not found.");
  } catch (e) {
    console.error(e);
    return fail(500, "Something went wrong on the server. Try again.");
  }
};

export { cleanCSV };
