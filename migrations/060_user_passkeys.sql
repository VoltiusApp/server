CREATE TABLE user_passkeys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    credential    JSONB NOT NULL,
    name          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ NULL
);

CREATE INDEX idx_user_passkeys_user ON user_passkeys (user_id);

CREATE TABLE passkey_ceremonies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL CHECK (purpose IN ('sign_in', 'step_up', 'register')),
    handle_hash TEXT NOT NULL UNIQUE,
    binding     TEXT NULL,
    return_to   JSONB NOT NULL,
    name        TEXT NULL,
    state       JSONB NULL,
    credential  JSONB NULL,
    code_hash   TEXT NULL UNIQUE,
    consumed_at TIMESTAMPTZ NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_passkey_ceremonies_expiry ON passkey_ceremonies (expires_at);
