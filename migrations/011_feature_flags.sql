CREATE TABLE user_feature_flags (
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  flag       TEXT NOT NULL,
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  set_by     TEXT NOT NULL,
  set_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, flag)
);
