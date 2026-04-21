CREATE TABLE terminal_sessions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id          UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    host_user_id     UUID NOT NULL REFERENCES users(id),
    connection_name  TEXT NOT NULL,
    visibility       TEXT NOT NULL DEFAULT 'public',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at         TIMESTAMPTZ
);

CREATE TABLE terminal_session_keys (
    session_id  UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    PRIMARY KEY (session_id, user_id)
);

CREATE INDEX idx_terminal_sessions_team ON terminal_sessions(team_id);
