CREATE TABLE team_vault_objects (
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    object_id   TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK (object_type IN (
        'connection', 'identity', 'key', 'folder', 'snippet', 'snippet_folder', 'port_forwarding_rule'
    )),
    name        TEXT,
    vault_id    UUID NOT NULL,
    folder_id   TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    updated_by  UUID NOT NULL REFERENCES users(id),
    PRIMARY KEY (team_id, object_id)
);

CREATE INDEX idx_team_vault_objects_team_type ON team_vault_objects(team_id, object_type);
CREATE INDEX idx_team_vault_objects_team_updated ON team_vault_objects(team_id, updated_at DESC);
CREATE INDEX idx_team_vault_objects_active ON team_vault_objects(team_id, object_type) WHERE deleted_at IS NULL;

CREATE TABLE team_vault_secrets (
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    secret_id   TEXT NOT NULL,
    object_id   TEXT NOT NULL,
    secret_type TEXT NOT NULL CHECK (secret_type IN (
        'connection_password', 'connection_key', 'identity_password', 'key_private', 'key_public', 'key_passphrase'
    )),
    ciphertext  TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID NOT NULL REFERENCES users(id),
    PRIMARY KEY (team_id, secret_id)
);

CREATE INDEX idx_team_vault_secrets_team_object ON team_vault_secrets(team_id, object_id);
