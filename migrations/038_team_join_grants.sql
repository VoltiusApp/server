-- Revocable, expiring, multi-use grants that admit a redeemer into a team as a
-- member. The role is baked in at creation: the redeemer supplies only the
-- secret, never a role, so a link can never be replayed for more privilege
-- than its creator chose.
--
-- Modelled on 037_terminal_session_grants: hashed secret, expires_at,
-- revoked_at, created_by. Deliberately NOT modelled on it in one respect —
-- there is no "one live grant per team" partial unique index. A team is meant
-- to have several live links at once (different roles, different audiences),
-- so nothing here needs the race-safe regeneration swap that index provides.
CREATE TABLE team_join_grants (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  secret_hash  BYTEA NOT NULL,
  role         TEXT NOT NULL,
  max_uses     INTEGER NOT NULL CHECK (max_uses > 0),
  uses         INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at   TIMESTAMPTZ,
  created_by   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The last line of defence behind the conditional UPDATE that consumes a
  -- use. If a future caller ever increments without the `uses < max_uses`
  -- guard, the write fails rather than over-issuing the link.
  CONSTRAINT team_join_grants_uses_within_max CHECK (uses <= max_uses)
);

CREATE UNIQUE INDEX idx_tjg_secret ON team_join_grants(secret_hash);

-- Serves the list endpoint, which only ever shows live grants.
CREATE INDEX idx_tjg_team_live ON team_join_grants(team_id) WHERE revoked_at IS NULL;
