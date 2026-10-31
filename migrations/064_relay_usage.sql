CREATE TABLE relay_identities (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ident   TEXT NOT NULL UNIQUE
);

CREATE TABLE relay_credentials (
    username   TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_relay_credentials_live ON relay_credentials(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE relay_usage (
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    month        DATE NOT NULL,
    egress_bytes BIGINT NOT NULL,
    PRIMARY KEY (user_id, month)
);

CREATE TABLE relay_budget (
    id           SMALLINT PRIMARY KEY CHECK (id = 1),
    window_bytes BIGINT NOT NULL,
    last_ok_at   TIMESTAMPTZ,
    tripped      BOOLEAN NOT NULL DEFAULT FALSE
);
