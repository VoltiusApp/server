ALTER TABLE users
    ADD COLUMN totp_secret TEXT NULL,
    ADD COLUMN totp_enabled_at TIMESTAMPTZ NULL,
    ADD COLUMN totp_last_step BIGINT NULL,
    ADD COLUMN totp_failed_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN totp_locked_until TIMESTAMPTZ NULL;

CREATE TABLE user_recovery_codes (
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TIMESTAMPTZ NULL,
    PRIMARY KEY (user_id, code_hash)
);
