// Ichiban x Motobuilt – People's Choice: Cloudflare Worker + D1.
// Pengunjung mengisi data singkat (untuk tim Ichiban Paint), lalu memberi 1 suara per kategori motor.

class HttpError extends Error {
  constructor(status, message, field) {
    super(message);
    this.status = status;
    this.field = field;
  }
}

const enc = new TextEncoder();
const SEC_HEADERS = {
  'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet, noimageindex',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
};
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SEC_HEADERS, ...headers },
  });

const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function fromB64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const cleanML = (v, max = 1500) => String(v ?? '').replace(/\r/g, '').replace(/[\u0000-\u0009\u000b-\u001f\u007f]+/g, ' ').replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim().slice(0, max);
const clean = (v, max = 200) => String(v ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
function normalizePhone(v) {
  let d = String(v ?? '').replace(/[^\d+]/g, '').replace(/\+/g, '');
  if (d.startsWith('0')) d = '62' + d.slice(1);
  else if (d.startsWith('8')) d = '62' + d;
  return d;
}
const isValidPhone = (p) => /^628\d{8,12}$/.test(p);
const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;
const csvCell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
};
const csv = (lines, filename) =>
  new Response('﻿' + lines.join('\r\n'), {
    headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${filename}"`, 'Cache-Control': 'no-store', ...SEC_HEADERS },
  });

function sniffImage(b) {
  if (b.length < 12) return null;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp';
  return null;
}
const MAX_PHOTO = 700_000; // byte setelah decode (batas baris D1 ±2 MB)

/* ------------------------------- Sesi & keamanan ------------------------------- */

const secretOf = (env) => env.SESSION_SECRET || (env.ADMIN_PASSWORD ? 'pc:' + env.ADMIN_PASSWORD : '');
async function hmac(env, s) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secretOf(env)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(s))));
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function sameSecret(a, b) {
  const h = async (x) => b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(x)))));
  return safeEq(await h(a), await h(b));
}
async function sign(env, payload) {
  const b = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b}.${await hmac(env, b)}`;
}
async function verify(env, tok) {
  if (!tok || !tok.includes('.') || !secretOf(env)) return null;
  const [b, h] = tok.split('.');
  if (!safeEq(h, await hmac(env, b))) return null;
  try {
    const p = JSON.parse(atob(b.replace(/-/g, '+').replace(/_/g, '/')));
    return p.exp > Date.now() ? p : null;
  } catch {
    return null;
  }
}
function cookieOf(req, name) {
  for (const part of (req.headers.get('Cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
async function requireAdmin(env, req) {
  const s = await verify(env, cookieOf(req, 'pc_admin'));
  if (!s || s.role !== 'admin') throw new HttpError(401, 'Silakan login terlebih dahulu.');
}
async function currentVoter(env, req) {
  const s = await verify(env, cookieOf(req, 'pc_voter'));
  if (!s || !s.v) return null;
  return (await env.DB.prepare('SELECT id, name, void FROM voters WHERE id = ?').bind(s.v).first()) || null;
}
async function ipHash(env, req) {
  const ip = req.headers.get('CF-Connecting-IP') || 'local';
  const d = await crypto.subtle.digest('SHA-256', enc.encode('ip:' + secretOf(env) + ip));
  return b64u(new Uint8Array(d)).slice(0, 16);
}
async function limit(env, req, name, max, windowMs = 10 * 60 * 1000) {
  const k = `${name}:${req.headers.get('CF-Connecting-IP') || 'local'}`;
  const now = Date.now();
  const r = await env.DB.batch([
    env.DB.prepare('DELETE FROM rate_hits WHERE t < ?').bind(now - 3600_000),
    env.DB.prepare('SELECT COUNT(*) AS c FROM rate_hits WHERE k = ? AND t > ?').bind(k, now - windowMs),
    env.DB.prepare('INSERT INTO rate_hits(k, t) VALUES(?, ?)').bind(k, now),
  ]);
  if (r[1].results[0].c >= max) throw new HttpError(429, 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.');
}
async function verifyTurnstile(env, token, req) {
  if (!env.TURNSTILE_SECRET) return;
  if (!token) throw new HttpError(400, 'Selesaikan verifikasi "Saya bukan robot" terlebih dahulu.');
  const fd = new FormData();
  fd.append('secret', env.TURNSTILE_SECRET);
  fd.append('response', String(token).slice(0, 2048));
  const ip = req.headers.get('CF-Connecting-IP');
  if (ip) fd.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd });
  const j = await r.json().catch(() => ({}));
  if (!j.success) throw new HttpError(400, 'Verifikasi gagal. Muat ulang halaman lalu coba lagi.');
}
function adminPath(env) {
  let v = String(env.ADMIN_PATH || '').trim().replace(/\/+$/, '');
  if (v && !v.startsWith('/')) v = '/' + v;
  return /^\/[A-Za-z0-9_-]{8,64}$/.test(v) ? v : '/admin';
}
async function readJson(req, max = 1_000_000) {
  if (Number(req.headers.get('Content-Length') || 0) > max) throw new HttpError(413, 'Data terlalu besar.');
  try {
    return await req.json();
  } catch {
    throw new HttpError(400, 'Format data tidak valid.');
  }
}

/* ---------------------------------- Pengaturan ---------------------------------- */

const DEFAULTS = {
  event_title: "People's Choice – Ichiban Paint x Motobuilt",
  intro: 'Pilih motor favoritmu di setiap kategori. Satu suara untuk setiap kategori, dan pilihan tidak bisa diubah.',
  status: 'soon', // soon | open | closed
  venue_code: '', // kode lokasi (ditampilkan panitia di venue); kosong = tidak dipakai
  show_results: '1', // tampilkan hasil ke publik setelah voting ditutup
  ip_limit: '40', // maks pendaftaran per jam dari satu alamat IP (wifi venue dipakai banyak orang)
};
async function getSettings(env) {
  const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
  const s = { ...DEFAULTS };
  for (const r of results) s[r.key] = r.value;
  return s;
}
const STATUSES = ['soon', 'open', 'closed'];

/* ----------------------------------- Data ----------------------------------- */

async function catalog(env) {
  const r = await env.DB.batch([
    env.DB.prepare('SELECT id, name FROM categories ORDER BY sort, id'),
    env.DB.prepare('SELECT id, category_id, number, name, owner, info, detail, active, (photo IS NOT NULL) AS has_photo FROM bikes ORDER BY CAST(number AS INTEGER), number, id'),
  ]);
  return r[0].results.map((c) => ({ ...c, bikes: r[1].results.filter((b) => b.category_id === c.id).map((b) => ({ ...b, has_photo: !!b.has_photo, active: !!b.active })) }));
}
async function tallies(env) {
  const { results } = await env.DB.prepare(
    `SELECT v.bike_id, COUNT(*) AS n FROM votes v JOIN voters r ON r.id = v.voter_id WHERE r.void = 0 GROUP BY v.bike_id`
  ).all();
  return new Map(results.map((x) => [x.bike_id, x.n]));
}
function withResults(cats, tally) {
  return cats.map((c) => {
    const total = c.bikes.reduce((a, b) => a + (tally.get(b.id) || 0), 0);
    const bikes = c.bikes.map((b) => ({ ...b, votes: tally.get(b.id) || 0, pct: total ? Math.round(((tally.get(b.id) || 0) / total) * 1000) / 10 : 0 }));
    bikes.sort((a, b) => b.votes - a.votes);
    return { ...c, total, bikes };
  });
}


/* ----------------------------------- Undi pemenang ----------------------------------- */

let drawReady = false;
async function ensureDrawTables(env) {
  if (drawReady) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS draws (id INTEGER PRIMARY KEY AUTOINCREMENT, prize TEXT NOT NULL, scope TEXT NOT NULL, scope_label TEXT, pool_size INTEGER NOT NULL, created_at TEXT NOT NULL)'),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS draw_winners (id INTEGER PRIMARY KEY AUTOINCREMENT, draw_id INTEGER NOT NULL, rank INTEGER NOT NULL, voter_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'menunggu')"),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS ix_dw_draw ON draw_winners(draw_id)'),
  ]);
  drawReady = true;
}
function randInt(n) { // acak seragam 0..n-1 (tanpa bias)
  const lim = Math.floor(0x100000000 / n) * n, a = new Uint32Array(1);
  do { crypto.getRandomValues(a); } while (a[0] >= lim);
  return a[0] % n;
}
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) { const j = randInt(i + 1); [arr[i], arr[j]] = [arr[j], arr[i]]; }
  return arr;
}
/* Pemenang motor per kelas + info seri */
function classWinners(results) {
  return results.filter((c) => c.bikes.length).map((c) => {
    const top = c.bikes[0] && c.bikes[0].votes ? c.bikes[0].votes : 0;
    const leaders = top ? c.bikes.filter((b) => b.votes === top) : [];
    return { id: c.id, name: c.name, total: c.total, top, tie: leaders.length > 1, leaders: leaders.map((b) => ({ id: b.id, number: b.number, name: b.name, owner: b.owner, votes: b.votes })), ranking: c.bikes.slice(0, 5).map((b) => ({ id: b.id, number: b.number, name: b.name, votes: b.votes })) };
  });
}
async function drawList(env) {
  const { results: ds } = await env.DB.prepare('SELECT * FROM draws ORDER BY id DESC LIMIT 100').all();
  const { results: ws } = await env.DB.prepare(
    `SELECT w.id, w.draw_id, w.rank, w.status, r.id AS voter_id, r.name, r.phone, r.community, r.city, r.void FROM draw_winners w JOIN voters r ON r.id = w.voter_id ORDER BY w.draw_id DESC, w.rank`
  ).all();
  return ds.map((d) => ({ ...d, winners: ws.filter((w) => w.draw_id === d.id) }));
}

/* ----------------------------------- Router ----------------------------------- */

async function handle(req, env) {
  const url = new URL(req.url);
  const { pathname: p } = url;
  const m = req.method;
  let g;

  const ap = adminPath(env);
  if (m === 'GET' && (p === ap || p === ap + '/')) {
    const res = await env.ASSETS.fetch(new Request(new URL('/admin', url), { headers: req.headers }));
    return new Response(res.body, { status: res.status, headers: new Headers({ ...Object.fromEntries(res.headers), 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' }) });
  }
  if (p === '/admin' || p === '/admin.html' || p.startsWith('/admin/')) return new Response('Tidak ditemukan', { status: 404, headers: { 'X-Robots-Tag': 'noindex' } });

  if (m === 'GET' && /^\/m\/[^/]{1,12}$/.test(p)) {
    const res = await env.ASSETS.fetch(new Request(new URL('/', url), { headers: req.headers }));
    return new Response(res.body, { status: res.status, headers: new Headers({ ...Object.fromEntries(res.headers), 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' }) });
  }
  if (!p.startsWith('/api/')) return env.ASSETS.fetch(req);

  /* ---------------- Publik ---------------- */
  if (m === 'GET' && p === '/api/config') {
    const s = await getSettings(env);
    const cats = (await catalog(env)).map((c) => ({ ...c, bikes: c.bikes.filter((b) => b.active) }));
    const out = {
      title: s.event_title, intro: s.intro, status: s.status, needs_code: !!s.venue_code,
      turnstile_site_key: env.TURNSTILE_SITE_KEY || '', categories: cats,
    };
    if (s.status === 'closed' && s.show_results === '1') out.results = withResults(cats, await tallies(env));
    return json(out);
  }

  if (m === 'GET' && p === '/api/me') {
    const v = await currentVoter(env, req);
    if (!v || v.void) return json({ voter: null });
    const { results } = await env.DB.prepare('SELECT category_id, bike_id FROM votes WHERE voter_id = ?').bind(v.id).all();
    return json({ voter: { name: v.name }, votes: Object.fromEntries(results.map((x) => [x.category_id, x.bike_id])) });
  }

  if (m === 'GET' && (g = p.match(/^\/api\/photo\/(\d+)$/))) {
    const b = await env.DB.prepare('SELECT photo, photo_mime FROM bikes WHERE id = ?').bind(Number(g[1])).first();
    if (!b || !b.photo) return new Response('Tidak ditemukan', { status: 404 });
    return new Response(fromB64(b.photo), { headers: { 'Content-Type': b.photo_mime, 'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' } });
  }

  if (m === 'POST' && p === '/api/join') {
    const s = await getSettings(env);
    if (s.status !== 'open') throw new HttpError(403, s.status === 'closed' ? 'Voting sudah ditutup.' : 'Voting belum dibuka.');
    const existing = await currentVoter(env, req);
    if (existing && !existing.void) return json({ ok: true, existing: true }); // satu perangkat = satu pemilih
    await limit(env, req, 'join', Math.min(500, Math.max(3, parseInt(s.ip_limit, 10) || 40)), 3600_000);
    const b = await readJson(req, 20_000);
    if (s.venue_code) {
      await limit(env, req, 'code', 20);
      if (!(await sameSecret(String(b.code || '').trim().toLowerCase(), s.venue_code.trim().toLowerCase()))) throw new HttpError(400, 'Kode lokasi salah. Tanyakan ke panitia di lokasi acara.', 'code');
    }
    const d = {
      name: clean(b.name, 80), phone: normalizePhone(b.phone), email: clean(b.email, 120).toLowerCase(),
      community: clean(b.community, 60), motor: clean(b.motor, 80), city: clean(b.city, 60),
      age: parseInt(b.age, 10), gender: b.gender === 'L' || b.gender === 'P' ? b.gender : '',
    };
    if (d.name.length < 2) throw new HttpError(400, 'Nama wajib diisi.', 'name');
    if (!isValidPhone(d.phone)) throw new HttpError(400, 'Nomor HP tidak valid. Contoh: 0812xxxxxxxx.', 'phone');
    if (!Number.isInteger(d.age) || d.age < 5 || d.age > 90) throw new HttpError(400, 'Umur wajib diisi (angka).', 'age');
    if (!d.gender) throw new HttpError(400, 'Pilih jenis kelamin.', 'gender');
    if (d.community.length < 2) throw new HttpError(400, 'Komunitas wajib diisi. Tulis "Tanpa komunitas" kalau kamu datang sendiri.', 'community');
    if (d.city.length < 2) throw new HttpError(400, 'Domisili wajib diisi.', 'city');
    if (d.motor.length < 2) throw new HttpError(400, 'Motor yang digunakan wajib diisi.', 'motor');
    if (d.email && !isValidEmail(d.email)) throw new HttpError(400, 'Format email tidak valid.', 'email');
    if (!b.consent) throw new HttpError(400, 'Anda harus menyetujui penggunaan data untuk ikut memilih.', 'consent');
    await verifyTurnstile(env, b.turnstile, req);
    let id;
    try {
      const r = await env.DB.prepare(
        `INSERT INTO voters(phone, name, email, age, gender, community, motor, city, consent_mkt, ip, ua, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(d.phone, d.name, d.email || null, d.age, d.gender, d.community || null, d.motor || null, d.city || null, b.consent_mkt ? 1 : 0,
        await ipHash(env, req), clean(req.headers.get('User-Agent'), 160), new Date().toISOString()).run();
      id = r.meta.last_row_id;
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Nomor HP ini sudah dipakai untuk memilih. Satu nomor hanya satu pemilih.', 'phone');
      throw e;
    }
    const maxAge = 7 * 86400;
    const secure = url.protocol === 'https:' ? '; Secure' : '';
    const tok = await sign(env, { v: id, exp: Date.now() + maxAge * 1000 });
    return json({ ok: true }, 201, { 'Set-Cookie': `pc_voter=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}` });
  }

  if (m === 'POST' && p === '/api/vote') {
    const s = await getSettings(env);
    if (s.status !== 'open') throw new HttpError(403, s.status === 'closed' ? 'Voting sudah ditutup.' : 'Voting belum dibuka.');
    const v = await currentVoter(env, req);
    if (!v || v.void) throw new HttpError(401, 'Daftar dulu untuk memilih.');
    await limit(env, req, 'vote', 120);
    const b = await readJson(req, 2_000);
    const bike = await env.DB.prepare('SELECT id, category_id FROM bikes WHERE id = ? AND category_id = ? AND active = 1').bind(Number(b.bike_id), Number(b.category_id)).first();
    if (!bike) throw new HttpError(400, 'Motor tidak valid untuk kategori ini.');
    try {
      await env.DB.prepare('INSERT INTO votes(voter_id, category_id, bike_id, created_at) VALUES(?,?,?,?)').bind(v.id, bike.category_id, bike.id, new Date().toISOString()).run();
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Kamu sudah memilih di kategori ini.');
      throw e;
    }
    return json({ ok: true });
  }

  /* ---------------- Admin ---------------- */
  if (m === 'POST' && p === '/api/admin/login') {
    await limit(env, req, 'login', 10);
    const b = await readJson(req, 5_000);
    if (!env.ADMIN_PASSWORD) throw new HttpError(500, 'ADMIN_PASSWORD belum diatur di Cloudflare (Settings → Variables and Secrets).');
    if (!(await sameSecret(String(b.password || ''), env.ADMIN_PASSWORD))) throw new HttpError(401, 'Password salah.');
    const maxAge = 12 * 3600;
    const token = await sign(env, { role: 'admin', exp: Date.now() + maxAge * 1000 });
    const secure = url.protocol === 'https:' ? '; Secure' : '';
    return json({ ok: true }, 200, { 'Set-Cookie': `pc_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}` });
  }
  if (m === 'POST' && p === '/api/admin/logout') return json({ ok: true }, 200, { 'Set-Cookie': 'pc_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });

  if (p.startsWith('/api/admin/')) {
    await requireAdmin(env, req);
    if (m === 'GET' && p === '/api/admin/me') return json({ role: 'admin' });

    if (m === 'GET' && p === '/api/admin/summary') {
      const r = await env.DB.batch([
        env.DB.prepare('SELECT COUNT(*) AS c, COALESCE(SUM(void = 1), 0) AS voided, COALESCE(SUM(consent_mkt = 1), 0) AS mkt FROM voters'),
        env.DB.prepare('SELECT COUNT(*) AS c FROM votes v JOIN voters r ON r.id = v.voter_id WHERE r.void = 0'),
        env.DB.prepare('SELECT ip, COUNT(*) AS c FROM voters WHERE void = 0 GROUP BY ip HAVING c >= 6 ORDER BY c DESC LIMIT 10'),
        env.DB.prepare("SELECT COALESCE(NULLIF(community, ''), '(tanpa komunitas)') AS k, COUNT(*) AS c FROM voters WHERE void = 0 GROUP BY k ORDER BY c DESC LIMIT 15"),
        env.DB.prepare("SELECT COALESCE(NULLIF(motor, ''), '(tidak diisi)') AS k, COUNT(*) AS c FROM voters WHERE void = 0 GROUP BY k ORDER BY c DESC LIMIT 15"),
        env.DB.prepare("SELECT CASE gender WHEN 'L' THEN 'Laki-laki' WHEN 'P' THEN 'Perempuan' ELSE '(tidak diisi)' END AS k, COUNT(*) AS c FROM voters WHERE void = 0 GROUP BY k ORDER BY c DESC"),
        env.DB.prepare("SELECT CASE WHEN age IS NULL THEN '(tidak diisi)' WHEN age < 18 THEN '< 18' WHEN age <= 24 THEN '18-24' WHEN age <= 34 THEN '25-34' WHEN age <= 44 THEN '35-44' ELSE '45+' END AS k, COUNT(*) AS c FROM voters WHERE void = 0 GROUP BY k ORDER BY k"),
        env.DB.prepare("SELECT COALESCE(NULLIF(city, ''), '(tidak diisi)') AS k, COUNT(*) AS c FROM voters WHERE void = 0 GROUP BY k ORDER BY c DESC LIMIT 15"),
      ]);
      const s = await getSettings(env);
      return json({
        status: s.status, voters: r[0].results[0], votes: r[1].results[0].c, suspicious: r[2].results,
        byCommunity: r[3].results, byMotor: r[4].results, byGender: r[5].results, byAge: r[6].results, byCity: r[7].results, results: withResults(await catalog(env), await tallies(env)),
      });
    }

    if (m === 'GET' && p === '/api/admin/catalog') return json(await catalog(env));
    if (m === 'POST' && p === '/api/admin/categories') {
      const b = await readJson(req, 2_000);
      const name = clean(b.name, 60);
      if (name.length < 2) throw new HttpError(400, 'Nama kategori wajib diisi.');
      const n = (await env.DB.prepare('SELECT COALESCE(MAX(sort), 0) + 1 AS n FROM categories').first()).n;
      await env.DB.prepare('INSERT INTO categories(name, sort) VALUES(?, ?)').bind(name, n).run();
      return json({ ok: true });
    }
    if (m === 'DELETE' && (g = p.match(/^\/api\/admin\/categories\/(\d+)$/))) {
      const c = await env.DB.prepare('SELECT COUNT(*) AS c FROM bikes WHERE category_id = ?').bind(Number(g[1])).first();
      if (c.c) throw new HttpError(409, 'Hapus dulu semua motor di kategori ini.');
      await env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(Number(g[1])).run();
      return json({ ok: true });
    }

    if (m === 'POST' && p === '/api/admin/import') {
      const b = await readJson(req, 900_000);
      const rows = (Array.isArray(b.rows) ? b.rows : []).slice(0, 500).map((r) => ({
        category: clean(r.category, 60), number: clean(r.number, 10), name: clean(r.name, 80), owner: clean(r.owner, 80), info: clean(r.info, 200), detail: cleanML(r.detail, 1500),
      })).filter((r) => r.category && r.number && r.name);
      if (!rows.length) throw new HttpError(400, 'Tidak ada baris yang valid di file.');
      const have = new Map((await env.DB.prepare('SELECT id, name FROM categories').all()).results.map((c) => [c.name.toLowerCase(), c.id]));
      const missing = [...new Set(rows.map((r) => r.category))].filter((n) => !have.has(n.toLowerCase()));
      let sort = (await env.DB.prepare('SELECT COALESCE(MAX(sort), 0) AS n FROM categories').first()).n;
      if (missing.length) await env.DB.batch(missing.map((n) => env.DB.prepare('INSERT INTO categories(name, sort) VALUES(?, ?)').bind(n, ++sort)));
      const cats = new Map((await env.DB.prepare('SELECT id, name FROM categories').all()).results.map((c) => [c.name.toLowerCase(), c.id]));
      const have2 = (await env.DB.prepare('SELECT id, number, category_id FROM bikes').all()).results;
      const bikes = new Map(have2.map((x) => [x.number.toLowerCase() + '|' + x.category_id, x.id]));
      const now = new Date().toISOString();
      let added = 0, updated = 0, removed = 0;
      const keep = new Set();
      const stmts = rows.map((r) => {
        const cid = cats.get(r.category.toLowerCase());
        const key = r.number.toLowerCase() + '|' + cid;
        const id = bikes.get(key);
        if (id) { keep.add(id); updated++; return env.DB.prepare('UPDATE bikes SET name = ?, owner = ?, info = ?, detail = ?, active = 1 WHERE id = ?').bind(r.name, r.owner || null, r.info || null, r.detail || null, id); }
        added++;
        return env.DB.prepare('INSERT INTO bikes(category_id, number, name, owner, info, detail, active, created_at) VALUES(?,?,?,?,?,?,1,?)').bind(cid, r.number, r.name, r.owner || null, r.info || null, r.detail || null, now);
      });
      if (b.replace) {
        // Sinkronkan: motor yang tidak ada lagi di file dihapus (atau dinonaktifkan kalau sudah punya suara).
        for (const x of have2) {
          if (keep.has(x.id)) continue;
          removed++;
          stmts.push(env.DB.prepare('DELETE FROM bikes WHERE id = ? AND NOT EXISTS (SELECT 1 FROM votes WHERE bike_id = ?)').bind(x.id, x.id));
          stmts.push(env.DB.prepare('UPDATE bikes SET active = 0 WHERE id = ?').bind(x.id));
        }
      }
      for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
      return json({ ok: true, added, updated, removed, categories: missing.length });
    }

    const bikeBody = async () => {
      const b = await readJson(req, 1_300_000);
      const d = { number: clean(b.number, 10), name: clean(b.name, 80), owner: clean(b.owner, 80), info: clean(b.info, 200), detail: cleanML(b.detail, 1500), photo: null, mime: null };
      if (!d.number) throw new HttpError(400, 'Nomor peserta wajib diisi.');
      if (d.name.length < 2) throw new HttpError(400, 'Nama motor wajib diisi.');
      if (b.photo) {
        const raw = String(b.photo).replace(/^data:[^,]*,/, '');
        let bytes;
        try { bytes = fromB64(raw); } catch { throw new HttpError(400, 'Foto tidak valid.'); }
        d.mime = sniffImage(bytes);
        if (!d.mime) throw new HttpError(400, 'Foto harus PNG, JPG, atau WebP.');
        if (bytes.length > MAX_PHOTO) throw new HttpError(413, 'Foto terlalu besar (maks 700 KB). Perkecil dulu.');
        d.photo = raw;
      }
      return { b, d };
    };
    if (m === 'POST' && p === '/api/admin/bikes') {
      const { b, d } = await bikeBody();
      const cat = await env.DB.prepare('SELECT id FROM categories WHERE id = ?').bind(Number(b.category_id)).first();
      if (!cat) throw new HttpError(400, 'Kategori tidak ditemukan.');
      await env.DB.prepare('INSERT INTO bikes(category_id, number, name, owner, info, detail, photo, photo_mime, active, created_at) VALUES(?,?,?,?,?,?,?,?,1,?)')
        .bind(cat.id, d.number, d.name, d.owner || null, d.info || null, d.detail || null, d.photo, d.mime, new Date().toISOString()).run();
      return json({ ok: true });
    }
    if (m === 'PUT' && (g = p.match(/^\/api\/admin\/bikes\/(\d+)$/))) {
      const { b, d } = await bikeBody();
      const id = Number(g[1]);
      await env.DB.prepare('UPDATE bikes SET number = ?, name = ?, owner = ?, info = ?, detail = ?, active = ? WHERE id = ?')
        .bind(d.number, d.name, d.owner || null, d.info || null, d.detail || null, b.active === false ? 0 : 1, id).run();
      if (d.photo) await env.DB.prepare('UPDATE bikes SET photo = ?, photo_mime = ? WHERE id = ?').bind(d.photo, d.mime, id).run();
      else if (b.remove_photo) await env.DB.prepare('UPDATE bikes SET photo = NULL, photo_mime = NULL WHERE id = ?').bind(id).run();
      return json({ ok: true });
    }
    if (m === 'DELETE' && (g = p.match(/^\/api\/admin\/bikes\/(\d+)$/))) {
      const id = Number(g[1]);
      await env.DB.batch([env.DB.prepare('DELETE FROM votes WHERE bike_id = ?').bind(id), env.DB.prepare('DELETE FROM bikes WHERE id = ?').bind(id)]);
      return json({ ok: true });
    }

    if (m === 'GET' && p === '/api/admin/voters') {
      const q = '%' + (url.searchParams.get('q') || '').replace(/[%_]/g, '') + '%';
      const { results } = await env.DB.prepare(
        `SELECT r.id, r.name, r.phone, r.email, r.age, r.gender, r.community, r.motor, r.city, r.consent_mkt, r.void, r.created_at,
                (SELECT COUNT(*) FROM votes v WHERE v.voter_id = r.id) AS votes,
                (SELECT COUNT(*) FROM voters x WHERE x.ip = r.ip) AS same_ip
         FROM voters r
         WHERE (?1 = '%%' OR r.name LIKE ?1 OR r.phone LIKE ?1 OR r.community LIKE ?1 OR r.motor LIKE ?1 OR r.email LIKE ?1)
         ORDER BY r.id DESC LIMIT 1000`
      ).bind(q).all();
      return json(results);
    }
    if (m === 'GET' && p === '/api/admin/voters.csv') {
      const [{ results: vs }, { results: vt }] = await env.DB.batch([
        env.DB.prepare('SELECT * FROM voters ORDER BY id'),
        env.DB.prepare('SELECT v.voter_id, c.name AS cat, b.number, b.name AS bike FROM votes v JOIN categories c ON c.id = v.category_id JOIN bikes b ON b.id = v.bike_id ORDER BY c.sort'),
      ]);
      const by = new Map();
      for (const x of vt) by.set(x.voter_id, [...(by.get(x.voter_id) || []), `${x.cat}: #${x.number} ${x.bike}`]);
      const head = ['No', 'Waktu', 'Nama', 'Umur', 'Jenis kelamin', 'No HP', 'Email', 'Komunitas', 'Motor yang digunakan', 'Domisili', 'Boleh dihubungi info promo', 'Status', 'Pilihan'];
      const lines = [head.map(csvCell).join(',')];
      vs.forEach((r, i) => lines.push([
        i + 1, new Date(r.created_at).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }), r.name, r.age, r.gender === 'L' ? 'Laki-laki' : r.gender === 'P' ? 'Perempuan' : '', r.phone, r.email, r.community, r.motor, r.city,
        r.consent_mkt ? 'Ya' : 'Tidak', r.void ? 'Dibatalkan' : 'Sah', (by.get(r.id) || []).join(' | '),
      ].map(csvCell).join(',')));
      return csv(lines, 'pemilih-people-choice.csv');
    }
    if (m === 'GET' && p === '/api/admin/suspicious') {
      const vs = (await env.DB.prepare('SELECT id, name, phone, age, gender, community, motor, city, ip, ua, created_at FROM voters WHERE void = 0 ORDER BY created_at').all()).results;
      const vt = (await env.DB.prepare('SELECT v.voter_id, v.bike_id, v.created_at, b.number, b.name AS bname, c.name AS cname FROM votes v JOIN bikes b ON b.id = v.bike_id JOIN categories c ON c.id = v.category_id').all()).results;
      const votesBy = new Map();
      for (const x of vt) { if (!votesBy.has(x.voter_id)) votesBy.set(x.voter_id, []); votesBy.get(x.voter_id).push(x); }
      const flags = new Map(vs.map((v) => [v.id, []]));
      const add = (v, t) => { const f = flags.get(v.id); if (!f.includes(t)) f.push(t); };
      const group = (keyFn, min, label) => {
        const g = new Map();
        for (const v of vs) { const k = keyFn(v); if (k) { if (!g.has(k)) g.set(k, []); g.get(k).push(v); } }
        for (const arr of g.values()) if (arr.length >= min) for (const v of arr) add(v, label(arr.length));
      };
      group((v) => v.ip, 6, (n) => `${n} pendaftar dari jaringan yang sama`);
      group((v) => v.ip && v.ua ? v.ip + '|' + v.ua : '', 3, (n) => `${n} pendaftar dari perangkat/jaringan yang sama`);
      group((v) => { const d = String(v.phone || '').replace(/\D/g, ''); return d.length >= 9 ? d.slice(0, -2) : ''; }, 3, (n) => `${n} nomor HP berurutan/mirip`);
      group((v) => String(v.name || '').toLowerCase().replace(/[^a-z]/g, ''), 2, (n) => `${n} pendaftar bernama sama`);
      group((v) => [v.community, v.motor, v.city, v.age, v.gender].map((x) => String(x ?? '').toLowerCase().trim()).join('|'), 3, (n) => `${n} pendaftar dengan data persis sama`);
      // pendaftaran beruntun: 3+ dalam 10 menit dari satu jaringan
      const byIp = new Map();
      for (const v of vs) if (v.ip) { if (!byIp.has(v.ip)) byIp.set(v.ip, []); byIp.get(v.ip).push(v); }
      for (const arr of byIp.values()) {
        for (let i = 0; i + 2 < arr.length; i++) {
          if (Date.parse(arr[i + 2].created_at) - Date.parse(arr[i].created_at) <= 10 * 60 * 1000) { for (let j = i; j <= i + 2; j++) add(arr[j], 'mendaftar beruntun (3 dalam 10 menit) dari satu jaringan'); }
        }
      }
      for (const v of vs) {
        const nm = String(v.name || '').toLowerCase().replace(/[^a-z]/g, '');
        if (nm.length <= 2 || /^(.)\1+$/.test(nm) || !/[aeiou]/.test(nm) || /(asdf|qwer|test|coba|xxxx|aaaa|zzzz)/.test(nm)) add(v, 'nama tidak wajar');
        const mine = votesBy.get(v.id) || [];
        if (mine.length && mine.every((x) => Date.parse(x.created_at) - Date.parse(v.created_at) < 3000)) add(v, 'memilih kurang dari 3 detik setelah mendaftar');
      }
      const out = vs.filter((v) => flags.get(v.id).length).map((v) => ({
        id: v.id, name: v.name, phone: v.phone, age: v.age, community: v.community, motor: v.motor, city: v.city, created_at: v.created_at,
        net: String(v.ip || '').slice(0, 6), flags: flags.get(v.id), votes: (votesBy.get(v.id) || []).length,
      })).sort((a, b) => b.flags.length - a.flags.length || b.votes - a.votes).slice(0, 300);
      // motor yang menerima banyak suara dari pemilih mencurigakan
      const flagged = new Set(vs.filter((v) => flags.get(v.id).length).map((v) => v.id));
      const bm = new Map();
      for (const x of vt) {
        if (!votesBy.has(x.voter_id) || !flags.has(x.voter_id)) continue;
        const e = bm.get(x.bike_id) || { number: x.number, name: x.bname, category: x.cname, total: 0, flagged: 0 };
        e.total++; if (flagged.has(x.voter_id)) e.flagged++; bm.set(x.bike_id, e);
      }
      const bikes = [...bm.values()].filter((b) => b.flagged >= 2).sort((a, b) => b.flagged / b.total - a.flagged / a.total || b.flagged - a.flagged).slice(0, 25);
      return json({ voters: out, bikes, total: vs.length, flagged: flagged.size });
    }

    if (m === 'POST' && (g = p.match(/^\/api\/admin\/voters\/(\d+)\/void$/))) {
      const b = await readJson(req, 500);
      await env.DB.prepare('UPDATE voters SET void = ? WHERE id = ?').bind(b.void ? 1 : 0, Number(g[1])).run();
      return json({ ok: true });
    }


    /* ---- Undi pemenang ---- */
    if (m === 'GET' && p === '/api/admin/draw') {
      await ensureDrawTables(env);
      const st = await getSettings(env);
      const res = withResults(await catalog(env), await tallies(env));
      const pool = await env.DB.prepare('SELECT COUNT(DISTINCT r.id) AS c FROM voters r JOIN votes v ON v.voter_id = r.id WHERE r.void = 0').first();
      return json({ status: st.status, pool: pool.c, classes: classWinners(res), draws: await drawList(env) });
    }
    if (m === 'POST' && p === '/api/admin/draw') {
      await ensureDrawTables(env);
      const b = await readJson(req, 2000);
      const st = await getSettings(env);
      if (st.status === 'open' && !b.force) throw new HttpError(409, 'Voting masih dibuka. Tutup voting dulu, atau konfirmasi untuk tetap mengundi.');
      const prize = clean(b.prize, 120) || 'Hadiah pemilih';
      const backups = Math.min(5, Math.max(0, parseInt(b.backups, 10) || 0));
      let scope = 'all', label = 'Semua pemilih sah', bikeId = null;
      if (typeof b.scope === 'string' && (g = b.scope.match(/^bike:(\d+)$/))) {
        bikeId = Number(g[1]);
        const bk = await env.DB.prepare('SELECT b.number, b.name, c.name AS cat FROM bikes b JOIN categories c ON c.id = b.category_id WHERE b.id = ?').bind(bikeId).first();
        if (!bk) throw new HttpError(404, 'Motor tidak ditemukan.');
        scope = 'bike:' + bikeId; label = `Pemilih motor #${bk.number} ${bk.name} (${bk.cat})`;
      }
      const sql = `SELECT DISTINCT r.id FROM voters r JOIN votes v ON v.voter_id = r.id
        WHERE r.void = 0 ${bikeId ? 'AND v.bike_id = ?1' : ''}
          AND r.id NOT IN (SELECT voter_id FROM draw_winners WHERE rank = 1 OR status IN ('diterima','gugur'))
        ORDER BY r.id`;
      const { results } = await (bikeId ? env.DB.prepare(sql).bind(bikeId) : env.DB.prepare(sql)).all();
      const ids = results.map((x) => x.id);
      if (!ids.length) throw new HttpError(409, 'Tidak ada pemilih sah yang memenuhi syarat untuk diundi.');
      const picked = shuffle(ids).slice(0, 1 + backups);
      const d = await env.DB.prepare('INSERT INTO draws(prize, scope, scope_label, pool_size, created_at) VALUES(?,?,?,?,?)').bind(prize, scope, label, ids.length, new Date().toISOString()).run();
      const drawId = d.meta.last_row_id;
      await env.DB.batch(picked.map((vid, i) => env.DB.prepare('INSERT INTO draw_winners(draw_id, rank, voter_id) VALUES(?,?,?)').bind(drawId, i + 1, vid)));
      return json({ ok: true, id: drawId });
    }
    if (m === 'POST' && (g = p.match(/^\/api\/admin\/draw\/winner\/(\d+)$/))) {
      await ensureDrawTables(env);
      const b = await readJson(req, 500);
      const status = ['menunggu', 'diterima', 'gugur'].includes(b.status) ? b.status : 'menunggu';
      await env.DB.prepare('UPDATE draw_winners SET status = ? WHERE id = ?').bind(status, Number(g[1])).run();
      return json({ ok: true });
    }
    if (m === 'POST' && (g = p.match(/^\/api\/admin\/draw\/(\d+)\/delete$/))) {
      await ensureDrawTables(env);
      await env.DB.batch([env.DB.prepare('DELETE FROM draw_winners WHERE draw_id = ?').bind(Number(g[1])), env.DB.prepare('DELETE FROM draws WHERE id = ?').bind(Number(g[1]))]);
      return json({ ok: true });
    }

    if (m === 'GET' && p === '/api/admin/settings') return json(await getSettings(env));
    if (m === 'PUT' && p === '/api/admin/settings') {
      const b = await readJson(req, 10_000);
      const status = STATUSES.includes(b.status) ? b.status : 'soon';
      const vals = {
        event_title: clean(b.event_title, 120) || DEFAULTS.event_title, intro: clean(b.intro, 400), status,
        venue_code: clean(b.venue_code, 40), show_results: b.show_results ? '1' : '0',
        ip_limit: String(Math.min(500, Math.max(3, parseInt(b.ip_limit, 10) || 40))),
      };
      await env.DB.batch(Object.entries(vals).map(([k, v]) =>
        env.DB.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v)));
      return json({ ok: true });
    }
  }

  return json({ error: 'Tidak ditemukan.' }, 404);
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, field: e.field }, e.status);
      console.error(e);
      return json({ error: 'Terjadi kesalahan di server. Coba lagi.' }, 500);
    }
  },
};
