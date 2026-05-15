ALTER TABLE pending_invitations ADD COLUMN user_id UUID REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX ON pending_invitations(user_id) WHERE accepted_at IS NULL;
