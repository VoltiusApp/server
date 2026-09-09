-- team_vault_keys becomes one row per (team, user, epoch) instead of per
-- (team, user), so a key can be rotated without destroying the previous
-- epoch's wrapped copies while any row is still encrypted under it.
ALTER TABLE team_vault_keys DROP CONSTRAINT team_vault_keys_pkey;
ALTER TABLE team_vault_keys ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE team_vault_keys ADD PRIMARY KEY (team_id, user_id, key_version);
CREATE INDEX idx_tvk_team_version ON team_vault_keys(team_id, key_version);

-- Ciphertext gets an explicit epoch tag so a client always knows which key
-- to fetch to decrypt a given row, including one still on a superseded epoch.
ALTER TABLE team_vault_secrets ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE team_sync_blobs ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1;

-- Epoch ledger. "Current" for a team is MAX(key_version); no separate flag.
CREATE TABLE team_key_epochs (
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    key_version INTEGER NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID NOT NULL REFERENCES users(id),
    PRIMARY KEY (team_id, key_version)
);
