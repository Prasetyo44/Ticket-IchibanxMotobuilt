CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_qr ON tickets(qr_id) WHERE qr_id IS NOT NULL;
