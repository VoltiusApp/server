CREATE TABLE team_vault_keys (
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    wrapped_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX idx_tvk_team ON team_vault_keys(team_id);

CREATE TABLE team_sync_blobs (
    team_id     UUID NOT NULL PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
    blob        BYTEA NOT NULL,
    size_bytes  INTEGER NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID NOT NULL REFERENCES users(id)
);
