CREATE TABLE sync_blobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    blob        BYTEA NOT NULL,
    metadata    JSONB NOT NULL,
    size_bytes  INTEGER NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (user_id, device_id)
);

CREATE INDEX idx_sync_blobs_user ON sync_blobs(user_id);
