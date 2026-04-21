ALTER TABLE users
  ADD COLUMN is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN is_banned      BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN ban_reason     TEXT NULL,
  ADD COLUMN banned_at      TIMESTAMPTZ NULL,
  ADD COLUMN admin_notes    TEXT NULL,
  ADD COLUMN discount_pct   SMALLINT NULL CHECK (discount_pct BETWEEN 1 AND 100);

-- Admin access is controlled via ADMIN_EMAILS env var, no DB seed needed.
