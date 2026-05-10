CREATE TABLE audit_logs (
  id          BIGSERIAL PRIMARY KEY,
  team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  vault_id    UUID,
  actor_id    UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  action      TEXT NOT NULL,
  source      TEXT NOT NULL DEFAULT 'server',
  target_type TEXT,
  target_id   TEXT,
  target_name TEXT,
  metadata    JSONB,
  ip_address  INET,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_logs_team_id_created_at_idx ON audit_logs(team_id, created_at DESC);
CREATE INDEX audit_logs_actor_id_idx ON audit_logs(actor_id);
CREATE INDEX audit_logs_action_idx ON audit_logs(action);

ALTER TABLE teams ADD COLUMN IF NOT EXISTS audit_retention_days INTEGER NOT NULL DEFAULT 30;
