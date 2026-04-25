CREATE TABLE pending_invitations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  email        TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'member',
  invited_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  token        TEXT NOT NULL UNIQUE DEFAULT replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '7 days',
  accepted_at  TIMESTAMPTZ,
  UNIQUE(team_id, email)
);

CREATE INDEX ON pending_invitations(token);
CREATE INDEX ON pending_invitations(email) WHERE accepted_at IS NULL;
