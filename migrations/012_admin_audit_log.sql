CREATE TABLE admin_audit_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email  TEXT NOT NULL,
  target_id    UUID NULL REFERENCES users(id),
  action       TEXT NOT NULL,
  detail       JSONB NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_target ON admin_audit_log(target_id);
CREATE INDEX idx_audit_email  ON admin_audit_log(admin_email);
