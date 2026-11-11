ALTER TABLE team_enrollment_tokens ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ NULL;
