// Ichiban x Motobuilt Ticketing: Cloudflare Worker + D1.
// QR dari IMOS disimpan apa adanya (base64) di tabel qr_stock dan hanya ditampilkan di halaman tiket.

/* ---------------------------------- Util ---------------------------------- */

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
const randToken = (n = 18) => b64u(crypto.getRandomValues(new Uint8Array(n)));

const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ticketCode = () => {
  let s = '';
  for (const b of crypto.getRandomValues(new Uint8Array(8))) s += ALPHA[b % 32];
  return 'IMOS-' + s;
};

function toB64(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');

const clean = (v, max = 200) =>
  String(v ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const cleanMultiline = (v, max = 500) =>
  String(v ?? '').replace(/\r/g, '').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, '').trim().slice(0, max);
const normalizeNik = (v) => String(v ?? '').toUpperCase().replace(/\s+/g, '').slice(0, 30);
function normalizePhone(v) {
  let d = String(v ?? '').replace(/[^\d+]/g, '').replace(/\+/g, '');
  if (d.startsWith('0')) d = '62' + d.slice(1);
  else if (d.startsWith('8')) d = '62' + d;
  return d;
}
const isValidPhone = (p) => /^628\d{8,12}$/.test(p);
const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;

// Deteksi tipe file dari isi (bukan dari nama). Hanya PNG, JPG, WebP, PDF.
function sniffMime(b) {
  if (b.length < 12) return null;
  const at = (i, s) => [...s].every((c, k) => b[i + k] === c.charCodeAt(0));
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return ['image/png', 'png'];
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return ['image/jpeg', 'jpg'];
  if (at(0, '%PDF-')) return ['application/pdf', 'pdf'];
  if (at(0, 'RIFF') && at(8, 'WEBP')) return ['image/webp', 'webp'];
  return null;
}

const MAX_FILE = 1_000_000; // 1 MB per file (batas baris D1 sekitar 2 MB setelah base64)

/* ---------------------------------- Sesi admin ---------------------------------- */

const secretOf = (env) => env.SESSION_SECRET || (env.ADMIN_PASSWORD ? 'imos:' + env.ADMIN_PASSWORD : '');

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
  const s = await verify(env, cookieOf(req, 'imos_session'));
  if (!s || s.role !== 'admin') throw new HttpError(401, 'Silakan login terlebih dahulu.');
  return s;
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

// Kode akses karyawan: kalau diatur, form pendaftaran tidak terbuka tanpa kode (cookie bertanda tangan, 7 hari)
async function codeTag(env, code) {
  return (await hmac(env, 'gate:' + code)).slice(0, 16);
}
async function hasGate(env, req, s) {
  if (!s.access_code) return true;
  const g = await verify(env, cookieOf(req, 'imos_gate'));
  return !!g && g.role === 'gate' && g.ac === (await codeTag(env, s.access_code));
}

/* ---------------------------------- Pengaturan & kuota ---------------------------------- */

const DEFAULTS = {
  event_title: 'Ichiban x Motobuilt',
  event_date: '20–29 November 2026',
  event_time: '',
  venue: 'ICE BSD City',
  venue_address: '',
  dresscode: '',
  info: 'Tunjukkan QR Code pada tiket kepada panitia saat masuk. Satu QR Code hanya berlaku untuk satu orang dan satu kali scan.',
  contact: 'Tim IT / HRD',
  capacity: '0', // total tiket; 0 = tanpa batas
  max_tickets: '2', // khusus mode umum: maksimal tiket per orang (1–10)
  access_code: '', // kode akses karyawan (dibagikan HRD); kosong = tanpa kode
  registration_deadline: '', // YYYY-MM-DDTHH:mm (WIB); kosong = tanpa batas
  registration_open: '1',
  departments: [
    'Produksi', 'QC', 'R&D', 'Gudang', 'Purchasing', 'Finance',
    'HRD / GA', 'Sales & Marketing', 'IT', 'Teknik / Maintenance', 'Lainnya',
  ].join('\n'),
};

const maxTickets = (s) => Math.min(10, Math.max(1, parseInt(s.max_tickets, 10) || 2));
const parseSettings = (rows) => {
  const out = { ...DEFAULTS };
  for (const r of rows) if (r.key in DEFAULTS) out[r.key] = r.value;
  return out;
};
const departmentsOf = (s) => s.departments.split('\n').map((x) => x.trim()).filter(Boolean);

function isOpen(s) {
  if (s.registration_open !== '1') return false;
  if (s.registration_deadline) {
    const t = Date.parse(s.registration_deadline + ':00+07:00');
    if (!Number.isNaN(t) && Date.now() > t) return false;
  }
  return true;
}

// Satu putaran ke database untuk semua angka yang dibutuhkan
async function snapshot(env) {
  const r = await env.DB.batch([
    env.DB.prepare('SELECT key, value FROM settings'),
    env.DB.prepare("SELECT COUNT(*) AS regs, COALESCE(SUM(ticket_count), 0) AS tickets FROM registrations WHERE status = 'active'"),
    env.DB.prepare("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'available'), 0) AS available, COALESCE(SUM(status = 'assigned'), 0) AS assigned FROM qr_stock"),
  ]);
  const s = parseSettings(r[0].results);
  const usage = r[1].results[0];
  const qr = r[2].results[0];
  const cap = parseInt(s.capacity, 10) || 0;
  let remaining = cap ? Math.max(0, cap - usage.tickets) : null;
  remaining = remaining === null ? qr.available : Math.min(remaining, qr.available);
  return { s, usage, qr, cap, remaining, open: isOpen(s) };
}

async function publicConfig(env, req) {
  const { s, qr, cap, remaining, open } = await snapshot(env);
  const mode = modeOf(env);
  if (!(await hasGate(env, req, s))) return { locked: true, event_title: s.event_title, mode };
  let closedReason = null;
  if (!open) closedReason = 'Pendaftaran sudah ditutup.';
  else if (qr.total === 0) closedReason = 'Tiket belum tersedia. Silakan coba lagi nanti.';
  else if (remaining === 0) closedReason = 'Kuota tiket sudah habis.';
  return {
    event_title: s.event_title, event_date: s.event_date, event_time: s.event_time, venue: s.venue,
    venue_address: s.venue_address, dresscode: s.dresscode, info: s.info, contact: s.contact,
    locked: false, mode, turnstile_site_key: mode === 'umum' ? String(env.TURNSTILE_SITE_KEY || '') : '',
    max_tickets: mode === 'umum' ? maxTickets(s) : 2,
    departments: departmentsOf(s), capacity: cap, remaining,
    registration_deadline: s.registration_deadline, open: open && remaining !== 0, closedReason,
  };
}

/* ---------------------------------- Pendaftaran ---------------------------------- */

async function register(env, d, req) {
  const DB = env.DB;
  const umum = modeOf(env) === 'umum';
  const who = umum ? 'nomor HP' : 'ID karyawan';
  const pre = await DB.batch([
    DB.prepare('SELECT key, value FROM settings'),
    DB.prepare('SELECT COUNT(*) AS c FROM employees'),
    DB.prepare('SELECT 1 AS x FROM employees WHERE nik = ?').bind(d.nik),
    DB.prepare("SELECT 1 AS x FROM registrations WHERE nik = ? AND status = 'active'").bind(d.nik),
    DB.prepare("SELECT 1 AS x FROM registrations WHERE nik = ? AND status = 'cancelled' LIMIT 1").bind(d.nik),
    DB.prepare('SELECT 1 AS x FROM rereg_allow WHERE nik = ?').bind(d.nik),
    DB.prepare("SELECT 1 AS x FROM registrations WHERE phone = ? AND status = 'active'").bind(d.phone),
    DB.prepare("SELECT COALESCE(SUM(ticket_count), 0) AS tickets FROM registrations WHERE status = 'active'"),
    DB.prepare("SELECT COALESCE(SUM(status = 'available'), 0) AS available FROM qr_stock"),
  ]);
  const s = parseSettings(pre[0].results);
  if (!(await hasGate(env, req, s))) throw new HttpError(403, 'Masukkan kode akses terlebih dahulu (muat ulang halaman).');
  if (!isOpen(s)) throw new HttpError(403, 'Pendaftaran sudah ditutup.');
  if (!umum && !departmentsOf(s).includes(d.dept)) throw new HttpError(400, 'Bagian tidak valid.', 'dept');
  if (!umum && pre[1].results[0].c > 0 && !pre[2].results.length) {
    throw new HttpError(403, 'ID karyawan tidak ditemukan di daftar karyawan. Hubungi HRD / IT.', 'nik');
  }
  if (pre[3].results.length) {
    throw new HttpError(409, umum
      ? 'Nomor HP ini sudah mendaftar (maksimal 2 tiket per orang). Tiketmu bisa dibuka lewat tombol "Buka tiket saya".'
      : 'ID karyawan ini sudah mendaftar (maksimal 2 tiket per karyawan). Tiketmu bisa dibuka lewat tombol "Buka tiket saya".', umum ? 'phone' : 'nik');
  }
  if (pre[4].results.length && !pre[5].results.length) {
    throw new HttpError(403, `Pendaftaran untuk ${who} ini pernah dibatalkan, jadi tidak bisa mendaftar lagi. Hubungi panitia kalau perlu tiket baru.`, umum ? 'phone' : 'nik');
  }
  if (pre[6].results.length) throw new HttpError(409, 'Nomor HP ini sudah dipakai pendaftar lain.', 'phone');
  if (umum) {
    const em = await DB.prepare("SELECT 1 AS x FROM registrations WHERE email = ? AND status = 'active'").bind(d.email).first();
    if (em) throw new HttpError(409, 'Email ini sudah dipakai pendaftar lain.', 'email');
  }

  const cap = parseInt(s.capacity, 10) || 0;
  let rem = pre[8].results[0].available;
  if (cap) rem = Math.min(rem, Math.max(0, cap - pre[7].results[0].tickets));
  if (rem <= 0) throw new HttpError(409, 'Kuota tiket sudah habis.');
  if (umum && d.ticket_count > maxTickets(s)) throw new HttpError(400, `Maksimal ${maxTickets(s)} tiket per orang.`, 'ticket_count');
  if (d.ticket_count > rem) throw new HttpError(409, `Sisa tiket hanya ${rem}. Kurangi jumlah tiket.`, 'ticket_count');

  // Satu batch = satu transaksi: pendaftaran, pengambilan QR dari stok, dan pembuatan tiket berhasil semua atau batal semua.
  const token = randToken();
  const n = d.ticket_count;
  const people = [{ seq: 1, kind: umum ? 'public' : 'employee', holder: d.name }];
  if (umum) d.guest_names.forEach((g, i) => people.push({ seq: i + 2, kind: 'guest', holder: g }));
  else if (n === 2) people.push({ seq: 2, kind: 'guest', holder: d.guest_name });
  const stmts = [
    DB.prepare(
      `INSERT INTO registrations(token, nik, name, dept, address, email, phone, ticket_count, guest_name, notes, created_at)
       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(token, d.nik, d.name, d.dept, d.address, d.email, d.phone, n, d.guest_name || null, d.notes || null, new Date().toISOString()),
    DB.prepare(
      `UPDATE qr_stock SET status = 'assigned', reg_id = (SELECT id FROM registrations WHERE token = ?1)
       WHERE id IN (SELECT id FROM qr_stock WHERE status = 'available' ORDER BY id LIMIT ?2)`
    ).bind(token, n),
    // Kalau stok ternyata kurang (dua orang mendaftar bersamaan), baris NULL ini melanggar NOT NULL dan membatalkan semuanya
    DB.prepare(
      `INSERT INTO guard(x) SELECT NULL WHERE (SELECT COUNT(*) FROM qr_stock WHERE reg_id = (SELECT id FROM registrations WHERE token = ?1)) < ?2`
    ).bind(token, n),
  ];
  for (const p of people) {
    stmts.push(
      DB.prepare(
        `INSERT INTO tickets(code, reg_id, seq, kind, holder_name, qr_id, file_token)
         SELECT ?1, r.id, ?2, ?3, ?4, (SELECT id FROM qr_stock WHERE reg_id = r.id ORDER BY id LIMIT 1 OFFSET ?5), ?6
         FROM registrations r WHERE r.token = ?7`
      ).bind(ticketCode(), p.seq, p.kind, p.holder, p.seq - 1, randToken(), token)
    );
  }
  stmts.push(DB.prepare('DELETE FROM rereg_allow WHERE nik = ?').bind(d.nik)); // izin daftar ulang hanya sekali pakai
  try {
    await DB.batch(stmts);
  } catch (e) {
    const m = String(e.message || e);
    if (/guard\.x|NOT NULL constraint failed: guard/i.test(m)) throw new HttpError(409, 'Kuota tiket sudah habis.');
    if (/registrations\.nik/i.test(m)) throw new HttpError(409, umum ? 'Nomor HP ini sudah mendaftar.' : 'ID karyawan ini sudah mendaftar.', umum ? 'phone' : 'nik');
    if (/registrations\.email/i.test(m)) throw new HttpError(409, 'Email ini sudah dipakai pendaftar lain.', 'email');
    if (/registrations\.phone/i.test(m)) throw new HttpError(409, 'Nomor HP ini sudah dipakai pendaftar lain.', 'phone');
    throw e;
  }
  return { token };
}

async function cancelRegistration(env, id, by = 'admin') {
  const DB = env.DB;
  const r = await DB.batch([
    DB.prepare("UPDATE registrations SET status = 'cancelled', cancelled_at = ?1, cancelled_by = ?2 WHERE id = ?3 AND status = 'active'").bind(
      new Date().toISOString(), by, id
    ),
    // QR kembali ke stok untuk karyawan lain; hubungan tiket lama dengan file diputus
    DB.prepare(
      "UPDATE qr_stock SET status = 'available', reg_id = NULL WHERE reg_id = ?1 AND (SELECT status FROM registrations WHERE id = ?1) = 'cancelled'"
    ).bind(id),
    DB.prepare("UPDATE tickets SET qr_id = NULL, file_token = NULL WHERE reg_id = ?1 AND (SELECT status FROM registrations WHERE id = ?1) = 'cancelled'").bind(id),
  ]);
  return r[0].meta.changes > 0;
}

// Pemilik tiket dibuktikan dengan ID karyawan + No HP yang sama dengan saat mendaftar (link saja tidak cukup)
// Mode umum: dibuktikan dengan email + No HP (bukan ID karyawan)
async function verifyOwner(env, token, nik, phone) {
  const umum = modeOf(env) === 'umum';
  const reg = await env.DB.prepare('SELECT id, nik, email, phone, status FROM registrations WHERE token = ?').bind(token).first();
  if (!reg) throw new HttpError(404, 'Tiket tidak ditemukan.');
  if (reg.status !== 'active') throw new HttpError(409, 'Tiket ini sudah dibatalkan.');
  const same = umum ? reg.email === clean(nik, 120).toLowerCase() : reg.nik === normalizeNik(nik);
  if (!same || reg.phone !== phone) {
    throw new HttpError(403, umum
      ? 'Data tidak cocok. Isi email dan nomor HP yang sama dengan saat mendaftar.'
      : 'Data tidak cocok. Isi ID karyawan dan nomor HP yang sama dengan saat mendaftar.');
  }
  return reg;
}

async function cancelByToken(env, token, nik, phone) {
  const reg = await verifyOwner(env, token, nik, phone);
  await cancelRegistration(env, reg.id, 'self');
}

const MAX_EXTRA = 5;

// Karyawan minta tiket di atas batas 2; panitia/HRD yang memutuskan
async function requestExtra(env, token, nik, phone, guests, reason) {
  const reg = await verifyOwner(env, token, nik, phone);
  const names = (Array.isArray(guests) ? guests : String(guests || '').split('\n')).map((x) => clean(x, 80)).filter((x) => x.length >= 2);
  if (!names.length) throw new HttpError(400, 'Isi nama tamu tambahan (satu nama per baris).');
  if (names.length > MAX_EXTRA) throw new HttpError(400, `Maksimal ${MAX_EXTRA} tiket tambahan per permintaan.`);
  try {
    await env.DB.prepare('INSERT INTO ticket_requests(reg_id, extra, guests, reason, created_at) VALUES(?, ?, ?, ?, ?)')
      .bind(reg.id, names.length, JSON.stringify(names), clean(reason, 300) || null, new Date().toISOString()).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) throw new HttpError(409, 'Permintaan sebelumnya masih menunggu keputusan panitia.');
    throw e;
  }
}

async function approveRequest(env, id) {
  const DB = env.DB;
  const rq = await DB.prepare(
    `SELECT rq.id, rq.reg_id, rq.extra, rq.guests, rq.status, r.status AS reg_status, r.ticket_count,
            (SELECT COALESCE(MAX(seq), 0) FROM tickets WHERE reg_id = rq.reg_id) AS max_seq,
            (SELECT COUNT(*) FROM qr_stock WHERE status = 'available') AS stock
     FROM ticket_requests rq JOIN registrations r ON r.id = rq.reg_id WHERE rq.id = ?`
  ).bind(id).first();
  if (!rq) throw new HttpError(404, 'Permintaan tidak ditemukan.');
  if (rq.status !== 'pending') throw new HttpError(409, 'Permintaan ini sudah diputuskan.');
  if (rq.reg_status !== 'active') throw new HttpError(409, 'Pendaftaran karyawan ini sudah dibatalkan.');
  if (rq.stock < rq.extra) throw new HttpError(409, `Stok QR tidak cukup (tersedia ${rq.stock}, diminta ${rq.extra}). Upload QR tambahan dari IMOS dulu.`);
  const names = JSON.parse(rq.guests);
  const now = new Date().toISOString();
  const stmts = [
    DB.prepare(
      `INSERT INTO guard(x) SELECT NULL WHERE (SELECT status FROM ticket_requests WHERE id = ?1) != 'pending'
         OR (SELECT status FROM registrations WHERE id = ?2) != 'active'`
    ).bind(rq.id, rq.reg_id),
    DB.prepare(
      `UPDATE qr_stock SET status = 'assigned', reg_id = ?1
       WHERE id IN (SELECT id FROM qr_stock WHERE status = 'available' ORDER BY id LIMIT ?2)`
    ).bind(rq.reg_id, rq.extra),
    DB.prepare('INSERT INTO guard(x) SELECT NULL WHERE (SELECT COUNT(*) FROM qr_stock WHERE reg_id = ?1) < ?2').bind(rq.reg_id, rq.ticket_count + rq.extra),
  ];
  names.forEach((name, i) => {
    stmts.push(
      DB.prepare(
        `INSERT INTO tickets(code, reg_id, seq, kind, holder_name, qr_id, file_token)
         VALUES(?1, ?2, ?3, 'guest', ?4,
           (SELECT id FROM qr_stock q WHERE q.reg_id = ?2 AND NOT EXISTS (SELECT 1 FROM tickets t WHERE t.qr_id = q.id) ORDER BY id LIMIT 1), ?5)`
      ).bind(ticketCode(), rq.reg_id, rq.max_seq + 1 + i, name, randToken())
    );
  });
  stmts.push(
    DB.prepare('UPDATE registrations SET ticket_count = ticket_count + ?1 WHERE id = ?2').bind(rq.extra, rq.reg_id),
    DB.prepare("UPDATE ticket_requests SET status = 'approved', decided_at = ?1 WHERE id = ?2").bind(now, rq.id)
  );
  try {
    await DB.batch(stmts);
  } catch (e) {
    if (/guard/i.test(String(e.message))) throw new HttpError(409, 'Stok atau status berubah saat diproses. Muat ulang lalu coba lagi.');
    throw e;
  }
}

/* ---------------------------------- Admin: data ---------------------------------- */

async function adminList(env, q, origin) {
  q = clean(q, 60);
  const like = `%${q}%`;
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.token, r.nik, r.name, r.dept, r.address, r.email, r.phone, r.ticket_count,
            r.guest_name, r.notes, r.status, r.created_at, r.cancelled_by, r.cancelled_at,
            (SELECT 1 FROM rereg_allow a WHERE a.nik = r.nik) AS rereg_allowed
     FROM registrations r
     WHERE (?1 = '' OR r.name LIKE ?2 OR r.nik LIKE ?2 OR r.dept LIKE ?2 OR r.guest_name LIKE ?2 OR r.phone LIKE ?2 OR r.email LIKE ?2)
     ORDER BY r.id DESC`
  ).bind(q, like).all();
  return results.map((r) => ({ ...r, url: `${origin}/t/${r.token}` }));
}

async function stats(env, origin) {
  const DB = env.DB;
  const snap = await snapshot(env);
  const r = await DB.batch([
    DB.prepare("SELECT dept, COUNT(*) AS regs, SUM(ticket_count) AS tickets FROM registrations WHERE status = 'active' GROUP BY dept ORDER BY tickets DESC"),
    DB.prepare("SELECT COUNT(*) AS c FROM registrations WHERE status = 'active' AND ticket_count >= 2"),
    DB.prepare('SELECT COUNT(*) AS c FROM employees'),
    DB.prepare("SELECT COUNT(*) AS c FROM employees e WHERE EXISTS (SELECT 1 FROM registrations r WHERE r.nik = e.nik AND r.status = 'active')"),
    DB.prepare("SELECT COUNT(*) AS c FROM ticket_requests WHERE status = 'pending'"),
  ]);
  return {
    registrations: snap.usage.regs,
    tickets: snap.usage.tickets,
    withGuest: r[1].results[0].c,
    capacity: snap.cap,
    remaining: snap.remaining,
    byDept: r[0].results,
    employees: r[2].results[0].c,
    employeesRegistered: r[2].results[0].c ? r[3].results[0].c : 0,
    open: snap.open,
    qr: snap.qr,
    pendingRequests: r[4].results[0].c,
    baseUrl: origin,
  };
}

async function importEmployees(env, text) {
  const rows = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const parts = line.split(/[,;\t]/).map((x) => x.trim());
    if (!parts[0]) continue;
    const nik = normalizeNik(parts[0]);
    if (nik === 'NIK' || nik === 'ID') continue; // baris judul
    if (!parts[1]) continue;
    rows.push({ n: nik, m: clean(parts[1], 80), d: clean(parts[2] || '', 60) });
  }
  if (rows.length) {
    await env.DB.prepare(
      `INSERT INTO employees(nik, name, dept)
       SELECT json_extract(value, '$.n'), json_extract(value, '$.m'), json_extract(value, '$.d') FROM json_each(?1) WHERE true
       ON CONFLICT(nik) DO UPDATE SET name = excluded.name, dept = excluded.dept`
    ).bind(JSON.stringify(rows)).run();
  }
  return rows.length;
}

const csvCell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // cegah formula injection di Excel
  return `"${s.replace(/"/g, '""')}"`;
};
const csv = (lines, filename) =>
  new Response('﻿' + lines.join('\r\n'), {
    headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${filename}"`, 'Cache-Control': 'no-store', ...SEC_HEADERS },
  });

/* ---------------------------------- Router ---------------------------------- */

async function readJson(req, max = 1_000_000) {
  const len = Number(req.headers.get('Content-Length') || 0);
  if (len > max) throw new HttpError(413, 'Data terlalu besar.');
  try {
    return await req.json();
  } catch {
    throw new HttpError(400, 'Format data tidak valid.');
  }
}

// Mode situs: 'karyawan' (default) atau 'umum'. Diatur lewat variabel MODE pada Worker masing-masing.
const modeOf = (env) => (String(env.MODE || '').trim().toLowerCase() === 'umum' ? 'umum' : 'karyawan');

// Cloudflare Turnstile (anti-bot gratis). Aktif hanya bila TURNSTILE_SECRET diisi.
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

// Alamat halaman admin. Isi variabel ADMIN_PATH di Cloudflare (mis. /pnl-x7k2m9q4w8t3) agar /admin tidak bisa ditebak.
function adminPath(env) {
  let v = String(env.ADMIN_PATH || '').trim().replace(/\/+$/, '');
  if (v && !v.startsWith('/')) v = '/' + v;
  return /^\/[A-Za-z0-9_-]{8,64}$/.test(v) ? v : '/admin';
}

async function handle(req, env, ctx) {
  const url = new URL(req.url);
  const { pathname: p } = url;
  const m = req.method;
  let g;

  /* ---- Halaman admin (alamat rahasia; /admin biasa dibuat 404 bila ADMIN_PATH diisi) ---- */
  const ap = adminPath(env);
  if (m === 'GET' && (p === ap || p === ap + '/')) {
    const res = await env.ASSETS.fetch(new Request(new URL('/admin', url), { headers: req.headers }));
    return new Response(res.body, { status: res.status, headers: new Headers({ ...Object.fromEntries(res.headers), 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' }) });
  }
  if (p === '/admin' || p === '/admin.html' || p.startsWith('/admin/')) return new Response('Tidak ditemukan', { status: 404, headers: { 'X-Robots-Tag': 'noindex' } });

  /* ---- Halaman tiket ---- */
  if (m === 'GET' && p.startsWith('/t/')) {
    const res = await env.ASSETS.fetch(new Request(new URL('/ticket', url), { headers: req.headers }));
    return new Response(res.body, { status: res.status, headers: new Headers({ ...Object.fromEntries(res.headers), 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' }) });
  }

  /* ---- File QR milik tiket (alamat berisi token acak panjang) ---- */
  if (m === 'GET' && (g = p.match(/^\/f\/([\w-]{1,64})$/))) {
    const f = await env.DB.prepare(
      `SELECT q.mime, q.data, t.code, t.seq, r.status AS reg_status
       FROM tickets t JOIN qr_stock q ON q.id = t.qr_id JOIN registrations r ON r.id = t.reg_id
       WHERE t.file_token = ?`
    ).bind(g[1]).first();
    if (!f) return new Response('Tidak ditemukan', { status: 404 });
    if (f.reg_status !== 'active') return new Response('Tiket ini sudah dibatalkan.', { status: 410 });
    const ext = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'application/pdf': 'pdf' }[f.mime];
    return new Response(fromB64(f.data), {
      headers: {
        'Content-Type': f.mime,
        'Content-Disposition': `inline; filename="tiket-${f.seq}-${f.code}.${ext}"`,
        'Cache-Control': 'private, no-store',
        'X-Robots-Tag': 'noindex',
        ...SEC_HEADERS,
      },
    });
  }

  if (!p.startsWith('/api/')) {
    // Mode umum + SEO_INDEX=1: halaman pendaftaran boleh ditemukan Google. Halaman tiket, file QR, API, dan admin tetap tersembunyi.
    if (m === 'GET' && modeOf(env) === 'umum' && env.SEO_INDEX === '1') {
      if (p === '/robots.txt') {
        return new Response('User-agent: *\nAllow: /\nDisallow: /t/\nDisallow: /f/\nDisallow: /api/\n', {
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
        });
      }
      if (p === '/' || p === '/index.html') {
        const res = await env.ASSETS.fetch(new Request(new URL('/', url), { headers: req.headers }));
        const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
        const s = parseSettings(results);
        const desc = `Pendaftaran tiket ${s.event_title}${s.event_date ? ', ' + s.event_date : ''}${s.venue ? ' di ' + s.venue : ''}. Daftar online, tiket QR langsung muncul di website.`;
        const e = (x) => String(x).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
        let html = await res.text();
        html = html.replace(/<meta name="robots"[^>]*>/,
          `<meta name="robots" content="index, follow">\n<meta name="description" content="${e(desc)}">\n<meta property="og:title" content="${e('Tiket ' + s.event_title)}">\n<meta property="og:description" content="${e(desc)}">\n<meta property="og:type" content="website">\n<meta property="og:image" content="${url.origin}/img/poster.jpg">`);
        const h = new Headers(res.headers);
        h.delete('X-Robots-Tag'); h.delete('Content-Length');
        h.set('Content-Type', 'text/html; charset=utf-8'); h.set('Cache-Control', 'public, max-age=300');
        return new Response(html, { status: res.status, headers: h });
      }
    }
    return env.ASSETS.fetch(req);
  }

  /* ---- API publik ---- */
  if (m === 'GET' && p === '/api/config') return json(await publicConfig(env, req));

  if (m === 'POST' && p === '/api/register') {
    await limit(env, req, 'register', 20);
    const b = await readJson(req, 50_000);
    const umum = modeOf(env) === 'umum';
    const d = {
      nik: umum ? '' : normalizeNik(b.nik), name: clean(b.name, 80), dept: umum ? 'Umum' : clean(b.dept, 60), address: umum ? '-' : clean(b.address, 300),
      email: clean(b.email, 120).toLowerCase(), phone: normalizePhone(b.phone), ticket_count: Number(b.ticket_count),
      guest_name: clean(b.guest_name, 80), notes: clean(b.notes, 200),
    };
    if (!umum && !/^[A-Z0-9._/-]{3,30}$/.test(d.nik)) throw new HttpError(400, 'ID karyawan tidak valid (3–30 karakter huruf/angka).', 'nik');
    if (d.name.length < 2) throw new HttpError(400, 'Nama lengkap wajib diisi.', 'name');
    if (!d.dept) throw new HttpError(400, 'Pilih bagian.', 'dept');
    if (!umum && d.address.length < 5) throw new HttpError(400, 'Alamat wajib diisi.', 'address');
    if (!isValidEmail(d.email)) throw new HttpError(400, 'Format email tidak valid.', 'email');
    if (!isValidPhone(d.phone)) throw new HttpError(400, 'Nomor HP/WhatsApp tidak valid (contoh: 0812 3456 7890).', 'phone');
    if (umum) {
      // Mode umum: jumlah tiket per orang bisa diatur admin (maks_tiket 1–10); satu nama tamu per tiket tambahan
      if (!Number.isInteger(d.ticket_count) || d.ticket_count < 1 || d.ticket_count > 10) throw new HttpError(400, 'Jumlah tiket tidak valid.', 'ticket_count');
      const gn = (Array.isArray(b.guest_names) ? b.guest_names : [b.guest_name]).map((x) => clean(x, 80)).filter(Boolean);
      const need = d.ticket_count - 1;
      if (gn.length < need || gn.slice(0, need).some((x) => x.length < 2)) throw new HttpError(400, `Isi nama lengkap untuk ${need} tamu yang ikut.`, 'guest_name');
      d.guest_names = gn.slice(0, need);
      d.guest_name = d.guest_names.join(', ');
    } else {
      if (![1, 2].includes(d.ticket_count)) throw new HttpError(400, 'Pilih jumlah tiket 1 atau 2.', 'ticket_count');
      if (d.ticket_count === 2 && d.guest_name.length < 2) throw new HttpError(400, 'Nama tamu yang ikut wajib diisi untuk 2 tiket.', 'guest_name');
      if (d.ticket_count === 1) d.guest_name = '';
    }
    if (b.consent !== true) throw new HttpError(400, 'Centang persetujuan data terlebih dahulu.', 'consent');
    if (umum) { d.nik = d.phone; await verifyTurnstile(env, b.turnstile, req); } // mode umum: kunci identitas = No HP
    const r = await register(env, d, req);
    return json({ ok: true, ticket_count: d.ticket_count, url: `/t/${r.token}` }, 201);
  }

  // Buka tiket lagi: wajib cocok ID karyawan + No HP
  if (m === 'POST' && p === '/api/lookup') {
    await limit(env, req, 'lookup', 6);
    const b = await readJson(req, 10_000);
    const umum = modeOf(env) === 'umum';
    const reg = await env.DB.prepare(`SELECT token FROM registrations WHERE ${umum ? 'email' : 'nik'} = ? AND phone = ? AND status = 'active'`)
      .bind(umum ? clean(b.email, 120).toLowerCase() : normalizeNik(b.nik), normalizePhone(b.phone)).first();
    if (!reg) throw new HttpError(404, 'Data tidak cocok, atau pendaftaran sudah dibatalkan.');
    return json({ ok: true, url: `/t/${reg.token}` });
  }

  if (m === 'POST' && (g = p.match(/^\/api\/ticket\/([\w-]{1,64})\/cancel$/))) {
    await limit(env, req, 'cancel', 8);
    const b = await readJson(req, 10_000);
    if (b.confirm !== true) throw new HttpError(400, 'Konfirmasi pembatalan diperlukan.');
    await cancelByToken(env, g[1], modeOf(env) === 'umum' ? b.email : b.nik, normalizePhone(b.phone));
    return json({ ok: true });
  }

  if (m === 'POST' && (g = p.match(/^\/api\/ticket\/([\w-]{1,64})\/request$/))) {
    await limit(env, req, 'request', 6);
    if (modeOf(env) === 'umum') throw new HttpError(403, 'Tiket tambahan tidak tersedia untuk pendaftaran umum.');
    const b = await readJson(req, 10_000);
    await requestExtra(env, g[1], b.nik, normalizePhone(b.phone), b.guests, b.reason);
    return json({ ok: true }, 201);
  }

  if (m === 'POST' && p === '/api/unlock') {
    await limit(env, req, 'unlock', 10);
    const b = await readJson(req, 2_000);
    const { results } = await env.DB.prepare("SELECT value FROM settings WHERE key = 'access_code'").all();
    const code = results[0]?.value || '';
    if (code && !(await sameSecret(String(b.code || '').trim(), code))) throw new HttpError(401, 'Kode akses salah. Tanyakan ke HRD.');
    const maxAge = 7 * 24 * 3600;
    const tok = await sign(env, { role: 'gate', ac: code ? await codeTag(env, code) : '', exp: Date.now() + maxAge * 1000 });
    const secure = url.protocol === 'https:' ? '; Secure' : '';
    return json({ ok: true }, 200, { 'Set-Cookie': `imos_gate=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}` });
  }

  if (m === 'GET' && (g = p.match(/^\/api\/ticket\/([\w-]{1,64})$/))) {
    const reg = await env.DB.prepare('SELECT id, name, dept, status FROM registrations WHERE token = ?').bind(g[1]).first();
    if (!reg) throw new HttpError(404, 'Tiket tidak ditemukan.');
    const [tk, snap, lastReq] = await Promise.all([
      env.DB.prepare(
        `SELECT t.seq, t.kind, t.holder_name, t.file_token, q.mime AS qr_mime
         FROM tickets t LEFT JOIN qr_stock q ON q.id = t.qr_id WHERE t.reg_id = ? ORDER BY t.seq`
      ).bind(reg.id).all(),
      env.DB.prepare('SELECT key, value FROM settings').all(),
      env.DB.prepare('SELECT extra, status FROM ticket_requests WHERE reg_id = ? ORDER BY id DESC LIMIT 1').bind(reg.id).first(),
    ]);
    const s = parseSettings(snap.results);
    return json({
      mode: modeOf(env),
      request: lastReq || null,
      event: { title: s.event_title, date: s.event_date, time: s.event_time, venue: s.venue, address: s.venue_address, dresscode: s.dresscode, info: s.info, contact: s.contact },
      registration: { name: reg.name, dept: reg.dept, status: reg.status },
      tickets: tk.results.map((t) => ({
        seq: t.seq, kind: t.kind, holder: t.holder_name, used: false,
        file: t.file_token && reg.status === 'active' ? { url: `/f/${t.file_token}`, mime: t.qr_mime } : null,
      })),
    });
  }

  /* ---- Login admin ---- */
  if (m === 'POST' && p === '/api/admin/login') {
    await limit(env, req, 'login', 10);
    const b = await readJson(req, 5_000);
    if (!env.ADMIN_PASSWORD) throw new HttpError(500, 'ADMIN_PASSWORD belum diatur di Cloudflare (Settings → Variables and Secrets).');
    if (!(await sameSecret(String(b.password || ''), env.ADMIN_PASSWORD))) throw new HttpError(401, 'Password salah.');
    const maxAge = 12 * 3600;
    const token = await sign(env, { role: 'admin', exp: Date.now() + maxAge * 1000 });
    const secure = url.protocol === 'https:' ? '; Secure' : '';
    return json({ ok: true, role: 'admin' }, 200, { 'Set-Cookie': `imos_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}` });
  }
  if (m === 'POST' && p === '/api/admin/logout') {
    return json({ ok: true }, 200, { 'Set-Cookie': 'imos_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  /* ---- Semua di bawah ini khusus admin ---- */
  if (p.startsWith('/api/admin/')) {
    await requireAdmin(env, req);

    if (m === 'GET' && p === '/api/admin/me') return json({ role: 'admin', mode: modeOf(env) });
    if (m === 'GET' && p === '/api/admin/stats') return json(await stats(env, url.origin));
    if (m === 'GET' && p === '/api/admin/registrations') return json(await adminList(env, url.searchParams.get('q') || '', url.origin));

    if (m === 'POST' && (g = p.match(/^\/api\/admin\/registrations\/(\d+)\/cancel$/))) {
      if (!(await cancelRegistration(env, Number(g[1])))) throw new HttpError(404, 'Pendaftaran tidak ditemukan / sudah dibatalkan.');
      return json({ ok: true });
    }
    if (m === 'POST' && (g = p.match(/^\/api\/admin\/registrations\/(\d+)\/allow-rereg$/))) {
      const r = await env.DB.prepare(
        "INSERT OR REPLACE INTO rereg_allow(nik, allowed_at) SELECT nik, ?1 FROM registrations WHERE id = ?2 AND status = 'cancelled'"
      ).bind(new Date().toISOString(), Number(g[1])).run();
      if (!r.meta.changes) throw new HttpError(404, 'Hanya pendaftaran yang sudah dibatalkan yang bisa diberi izin daftar ulang.');
      return json({ ok: true });
    }

    if (m === 'GET' && p === '/api/admin/requests') {
      const { results } = await env.DB.prepare(
        `SELECT rq.id, rq.extra, rq.guests, rq.reason, rq.status, rq.created_at, rq.decided_at,
                r.name, r.nik, r.dept, r.phone, r.ticket_count, r.status AS reg_status
         FROM ticket_requests rq JOIN registrations r ON r.id = rq.reg_id
         ORDER BY (rq.status = 'pending') DESC, rq.id DESC`
      ).all();
      return json(results.map((x) => ({ ...x, guests: JSON.parse(x.guests) })));
    }
    if (m === 'POST' && (g = p.match(/^\/api\/admin\/requests\/(\d+)\/approve$/))) {
      await approveRequest(env, Number(g[1]));
      return json({ ok: true });
    }
    if (m === 'POST' && (g = p.match(/^\/api\/admin\/requests\/(\d+)\/reject$/))) {
      const r = await env.DB.prepare("UPDATE ticket_requests SET status = 'rejected', decided_at = ? WHERE id = ? AND status = 'pending'")
        .bind(new Date().toISOString(), Number(g[1])).run();
      if (!r.meta.changes) throw new HttpError(409, 'Permintaan tidak ditemukan atau sudah diputuskan.');
      return json({ ok: true });
    }

    if (m === 'GET' && p === '/api/admin/export.csv') {
      const rows = await adminList(env, '', url.origin);
      const um = modeOf(env) === 'umum';
      const head = um
        ? ['No', 'Waktu Daftar', 'Nama', 'Email', 'No HP', 'Jumlah Tiket', 'Nama Tamu', 'Catatan', 'Status']
        : ['No', 'Waktu Daftar', 'ID Karyawan', 'Nama', 'Bagian', 'Alamat', 'Email', 'No HP', 'Jumlah Tiket', 'Nama Tamu', 'Catatan', 'Status'];
      const lines = [head.map(csvCell).join(',')];
      rows.slice().reverse().forEach((r, i) => {
        const t = new Date(r.created_at).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });
        lines.push((um
          ? [i + 1, t, r.name, r.email, r.phone, r.ticket_count, r.guest_name, r.notes, r.status]
          : [i + 1, t, r.nik, r.name, r.dept, r.address, r.email, r.phone, r.ticket_count, r.guest_name, r.notes, r.status]
        ).map(csvCell).join(','));
      });
      return csv(lines, 'peserta-imos.csv');
    }

    if (m === 'GET' && p === '/api/admin/settings') {
      const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
      return json(parseSettings(results));
    }
    if (m === 'PUT' && p === '/api/admin/settings') {
      const b = await readJson(req, 20_000);
      const cap = parseInt(b.capacity, 10);
      if (Number.isNaN(cap) || cap < 0) throw new HttpError(400, 'Kuota harus angka ≥ 0 (0 = tanpa batas).');
      const depts = cleanMultiline(b.departments, 1500).split('\n').map((x) => clean(x, 60)).filter(Boolean);
      if (!depts.length) throw new HttpError(400, 'Daftar bagian tidak boleh kosong.');
      const mt = Math.min(10, Math.max(1, parseInt(b.max_tickets, 10) || 2));
      const dl = clean(b.registration_deadline, 20);
      if (dl && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(dl)) throw new HttpError(400, 'Format batas pendaftaran tidak valid.');
      const vals = {
        event_title: clean(b.event_title, 120) || DEFAULTS.event_title,
        event_date: clean(b.event_date, 80), event_time: clean(b.event_time, 60), venue: clean(b.venue, 120),
        venue_address: clean(b.venue_address, 200), dresscode: clean(b.dresscode, 120), info: cleanMultiline(b.info, 400),
        contact: clean(b.contact, 120), capacity: String(cap), max_tickets: String(mt), access_code: clean(b.access_code, 40), registration_deadline: dl,
        registration_open: b.registration_open ? '1' : '0', departments: depts.join('\n'),
      };
      await env.DB.batch(
        Object.entries(vals).map(([k, v]) =>
          env.DB.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v)
        )
      );
      return json({ ok: true });
    }

    if (m === 'GET' && p === '/api/admin/employees') {
      const { results } = await env.DB.prepare('SELECT nik, name, dept FROM employees ORDER BY name').all();
      return json(results);
    }
    if (m === 'POST' && p === '/api/admin/employees/import') {
      const b = await readJson(req);
      return json({ ok: true, imported: await importEmployees(env, b.text) });
    }
    if (m === 'DELETE' && p === '/api/admin/employees') {
      await env.DB.prepare('DELETE FROM employees').run();
      return json({ ok: true });
    }
    if (m === 'GET' && p === '/api/admin/not-registered.csv') {
      const { results } = await env.DB.prepare(
        "SELECT nik, name, dept FROM employees e WHERE NOT EXISTS (SELECT 1 FROM registrations r WHERE r.nik = e.nik AND r.status = 'active') ORDER BY dept, name"
      ).all();
      return csv([['ID Karyawan', 'Nama', 'Bagian'].map(csvCell).join(','), ...results.map((e) => [e.nik, e.name, e.dept].map(csvCell).join(','))], 'belum-daftar-imos.csv');
    }

    /* ---- Stok QR IMOS ---- */
    // Upload satu file per request (body = isi file mentah); browser mengirim berurutan.
    if (m === 'POST' && p === '/api/admin/qr/upload') {
      if (Number(req.headers.get('Content-Length') || 0) > MAX_FILE + 1024) throw new HttpError(413, `File terlalu besar (maksimal ${MAX_FILE / 1_000_000} MB per file).`);
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) throw new HttpError(400, 'File kosong.');
      if (buf.byteLength > MAX_FILE) throw new HttpError(413, `File terlalu besar (maksimal ${MAX_FILE / 1_000_000} MB per file).`);
      const t = sniffMime(new Uint8Array(buf));
      if (!t) throw new HttpError(400, 'Format tidak didukung (hanya PNG, JPG, WebP, atau PDF).');
      const sha = hex(await crypto.subtle.digest('SHA-256', buf));
      const filename = clean(url.searchParams.get('name'), 120) || `tiket.${t[1]}`;
      // File yang isinya identik tidak masuk dua kali
      const r = await env.DB.prepare(
        `INSERT INTO qr_stock(filename, mime, size, sha256, data, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(sha256) DO NOTHING`
      ).bind(filename, t[0], buf.byteLength, sha, toB64(buf), new Date().toISOString()).run();
      return json(r.meta.changes ? { ok: true, id: r.meta.last_row_id } : { ok: true, duplicate: true });
    }
    if (m === 'GET' && p === '/api/admin/qr') {
      const r = await env.DB.batch([
        env.DB.prepare("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'available'), 0) AS available, COALESCE(SUM(status = 'assigned'), 0) AS assigned FROM qr_stock"),
        env.DB.prepare(
          `SELECT q.id, q.filename, q.mime, q.size, q.status, q.uploaded_at, t.seq, t.holder_name, r.name AS employee, r.status AS reg_status
           FROM qr_stock q
           LEFT JOIN tickets t ON t.qr_id = q.id
           LEFT JOIN registrations r ON r.id = t.reg_id
           ORDER BY q.id`
        ),
      ]);
      return json({ counts: r[0].results[0], items: r[1].results });
    }
    if (m === 'GET' && (g = p.match(/^\/api\/admin\/qr\/(\d+)\/file$/))) {
      const q = await env.DB.prepare('SELECT mime, data FROM qr_stock WHERE id = ?').bind(Number(g[1])).first();
      if (!q) return new Response('Tidak ditemukan', { status: 404 });
      return new Response(fromB64(q.data), { headers: { 'Content-Type': q.mime, 'Cache-Control': 'private, max-age=600', ...SEC_HEADERS } });
    }
    if (m === 'DELETE' && (g = p.match(/^\/api\/admin\/qr\/(\d+)$/))) {
      const r = await env.DB.prepare("DELETE FROM qr_stock WHERE id = ? AND status = 'available'").bind(Number(g[1])).run();
      if (!r.meta.changes) throw new HttpError(409, 'Hanya file yang belum dibagikan yang bisa dihapus.');
      return json({ ok: true });
    }
  }

  return json({ error: 'Tidak ditemukan.' }, 404);
}

export default {
  async fetch(req, env, ctx) {
    try {
      return await handle(req, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, field: e.field }, e.status);
      console.error(e);
      return json({ error: 'Terjadi kesalahan di server. Coba lagi.' }, 500);
    }
  },
};
