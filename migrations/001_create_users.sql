CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE,
    account_id          UUID NOT NULL UNIQUE,
    auth_hash           TEXT NOT NULL,
    public_key          TEXT NOT NULL,
    subscription_tier   TEXT NOT NULL DEFAULT 'free',
    trial_ends_at       TIMESTAMPTZ NULL,
    trial_used          BOOLEAN NOT NULL DEFAULT FALSE,
    ls_customer_id      TEXT NULL,
    ls_subscription_id  TEXT NULL,
    seat_count          INTEGER NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
