-- users.handle (035) is the sole human-facing identifier. display_name was a
-- second name for the same person and a weaker one: it defaulted to
-- split_part(email, '@', 1), so it leaked the email local part by construction.
ALTER TABLE users DROP COLUMN display_name;
