ALTER TABLE team_vault_keys ADD COLUMN fetched_at TIMESTAMPTZ;
-- Fetches were never recorded, so every existing wrap counts as delivered.
UPDATE team_vault_keys SET fetched_at = created_at;
