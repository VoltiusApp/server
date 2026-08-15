-- users.handle (035) is the sole human-facing identifier. display_name was a
-- second name for the same person and a weaker one: it defaulted to
-- split_part(email, '@', 1), so it leaked the email local part by construction.
--
-- DEPLOY WARNING: irreversible, no down-migration. The old server still
-- reads/writes display_name, so it cannot keep serving once this lands —
-- no rolling restart across this migration.
ALTER TABLE users DROP COLUMN display_name;
