ALTER TABLE pending_invitations ADD COLUMN role_ids UUID[] NOT NULL DEFAULT '{}';
