-- Soft deletion of users.
--
-- When an admin deletes a user, we mark `deleted_at` so the account is locked
-- and hidden from default queries. A nightly purge job (or an explicit
-- force-delete) removes the row once grace expires.
--
-- PII is intentionally kept intact during the grace window so a restore is
-- possible. Hard-delete cascades to dependent rows via existing ON DELETE
-- CASCADE foreign keys.

ALTER TABLE users
    ADD COLUMN deleted_at        TIMESTAMPTZ NULL,
    ADD COLUMN deletion_reason   TEXT NULL,
    ADD COLUMN deleted_by        TEXT NULL;

CREATE INDEX idx_users_deleted_at ON users (deleted_at) WHERE deleted_at IS NOT NULL;
