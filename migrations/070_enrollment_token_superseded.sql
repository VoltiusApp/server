ALTER TABLE team_enrollment_tokens ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ NULL;

UPDATE team_enrollment_tokens o SET superseded_at = o.revoked_at
WHERE o.superseded_at IS NULL AND o.revoked_at IS NOT NULL
  AND EXISTS (SELECT 1 FROM team_enrollment_tokens n WHERE n.team_id = o.team_id AND n.id <> o.id AND n.created_at = o.revoked_at);
