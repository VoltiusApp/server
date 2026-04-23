ALTER TABLE users ALTER COLUMN public_key DROP NOT NULL;
ALTER TABLE users ALTER COLUMN public_key SET DEFAULT NULL;
UPDATE users SET public_key = NULL WHERE public_key = '';
