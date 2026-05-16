ALTER TABLE users ADD COLUMN wrapped_user_secrets TEXT NULL;
-- NULL = account predates the refactor; migrated on next Tauri client login.
