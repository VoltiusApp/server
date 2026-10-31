CREATE TABLE device_rendezvous (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_device TEXT NOT NULL,
    to_device   TEXT NOT NULL,
    offer       BYTEA NOT NULL,
    answer      BYTEA,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_device_rendezvous_expires ON device_rendezvous(expires_at);
