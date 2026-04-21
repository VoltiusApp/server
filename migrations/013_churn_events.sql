CREATE TABLE churn_events (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  from_tier    TEXT NOT NULL,
  to_tier      TEXT NOT NULL,
  reason       TEXT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_churn_user ON churn_events(user_id);
CREATE INDEX idx_churn_time ON churn_events(created_at);
