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
  ticket_count INTEGER NOT NULL CHECK (ticket_count BETWEEN 1 AND 20),
  guest_name TEXT,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  cancelled_at TEXT,
  cancelled_by TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_reg_nik_active ON registrations(nik) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS ux_reg_phone_active ON registrations(phone) WHERE status = 'active';
CREATE TABLE IF NOT EXISTS rereg_allow (nik TEXT PRIMARY KEY, allowed_at TEXT NOT NULL);
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
CREATE TABLE IF NOT EXISTS guard (x INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rate_hits (k TEXT NOT NULL, t INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rate ON rate_hits(k, t);
