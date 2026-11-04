CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS employees (nik TEXT PRIMARY KEY, name TEXT NOT NULL, dept TEXT);

CREATE TABLE IF NOT EXISTS registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  nik TEXT NOT NULL,
  name TEXT NOT NULL,
  dept TEXT NOT NULL,
  address TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  -- Awalnya 1 atau 2; bisa bertambah kalau panitia menyetujui permintaan tiket tambahan
  ticket_count INTEGER NOT NULL CHECK (ticket_count BETWEEN 1 AND 20),
  guest_name TEXT,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  cancelled_at TEXT,
  cancelled_by TEXT
);
-- Satu ID karyawan dan satu No HP hanya boleh punya satu pendaftaran aktif (dijaga langsung oleh database)
CREATE UNIQUE INDEX IF NOT EXISTS ux_reg_nik_active ON registrations(nik) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS ux_reg_phone_active ON registrations(phone) WHERE status = 'active';

-- NIK yang pernah dibatalkan hanya boleh daftar lagi kalau panitia mengizinkan (sekali pakai)
CREATE TABLE IF NOT EXISTS rereg_allow (nik TEXT PRIMARY KEY, allowed_at TEXT NOT NULL);

-- Stok file QR asli dari IMOS. File disimpan base64 apa adanya (tidak diubah).
-- reg_id terisi selama QR dipegang pendaftaran aktif; kembali NULL kalau dibatalkan.
CREATE TABLE IF NOT EXISTS qr_stock (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  data TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'available',
  reg_id INTEGER,
  uploaded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_qr_status ON qr_stock(status, id);
CREATE INDEX IF NOT EXISTS ix_qr_reg ON qr_stock(reg_id);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  reg_id INTEGER NOT NULL REFERENCES registrations(id),
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL,
  holder_name TEXT NOT NULL,
  qr_id INTEGER,
  file_token TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_file_token ON tickets(file_token);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_reg_seq ON tickets(reg_id, seq);

-- Permintaan tiket tambahan dari karyawan (batas normal 2 tiket). Panitia/HRD menyetujui atau menolak.
CREATE TABLE IF NOT EXISTS ticket_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reg_id INTEGER NOT NULL REFERENCES registrations(id),
  extra INTEGER NOT NULL,
  guests TEXT NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  decided_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_req_pending ON ticket_requests(reg_id) WHERE status = 'pending';

-- Penjaga: INSERT NULL ke sini sengaja gagal supaya seluruh batch dibatalkan (stok habis saat balapan)
CREATE TABLE IF NOT EXISTS guard (x INTEGER NOT NULL);

-- Pembatas percobaan (login, buka tiket, batal)
CREATE TABLE IF NOT EXISTS rate_hits (k TEXT NOT NULL, t INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rate ON rate_hits(k, t);
