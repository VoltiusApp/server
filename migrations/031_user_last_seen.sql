-- Coarse liveness signal for dormant-account detection and retention metrics.
--
-- Deliberately a DATE, not a TIMESTAMPTZ: day granularity answers "is this
-- account still in use" and "how many accounts were active this month" without
-- recording when in the day someone works. The column is overwritten in place,
-- so it carries no history — there is no activity log to reconstruct.
--
-- NULL means "not seen since this column existed". Existing rows are left NULL
-- rather than backfilled from created_at, which would invent activity that
-- never happened.
ALTER TABLE users
    ADD COLUMN last_seen_on DATE NULL;

CREATE INDEX idx_users_last_seen_on ON users (last_seen_on);
