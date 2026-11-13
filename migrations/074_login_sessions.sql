-- One row per signed-in device. A session is live while its row exists, has not
-- expired, and its token_version still matches users.token_version.
CREATE TABLE login_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_version INT NOT NULL,
    device_name   TEXT,
    platform      TEXT,
    client        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX login_sessions_user_id ON login_sessions (user_id);
