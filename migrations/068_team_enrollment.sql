ALTER TABLE users ADD COLUMN IF NOT EXISTS email_proven_at TIMESTAMPTZ NULL;

CREATE OR REPLACE FUNCTION users_email_change_clears_proof() RETURNS trigger AS $$
BEGIN
  NEW.email_proven_at := NULL;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_email_change_clears_proof ON users;
CREATE TRIGGER users_email_change_clears_proof
  BEFORE UPDATE OF email ON users
  FOR EACH ROW WHEN (OLD.email IS DISTINCT FROM NEW.email)
  EXECUTE FUNCTION users_email_change_clears_proof();

CREATE TABLE IF NOT EXISTS team_enrollment_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  secret_hash BYTEA NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'member',
  allowed_domains TEXT[] NOT NULL DEFAULT '{}',
  require_approval BOOLEAN NOT NULL,
  expires_at TIMESTAMPTZ NULL,
  created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ NULL,
  last_used_at TIMESTAMPTZ NULL,
  CONSTRAINT team_enrollment_tokens_guard CHECK (cardinality(allowed_domains) > 0 OR require_approval)
);

CREATE UNIQUE INDEX IF NOT EXISTS team_enrollment_tokens_one_active
  ON team_enrollment_tokens (team_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS team_join_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_id UUID NULL REFERENCES team_enrollment_tokens(id) ON DELETE SET NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
  reason TEXT NULL CHECK (reason IN ('approval', 'email_unverified', 'seat_limit')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  decided_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS team_join_requests_one_pending
  ON team_join_requests (team_id, user_id) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS team_join_requests_pending_user
  ON team_join_requests (user_id) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS team_join_requests_token
  ON team_join_requests (token_id);
