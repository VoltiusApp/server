CREATE TABLE terminal_session_grants (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id   UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
  kind         TEXT NOT NULL CHECK (kind IN ('legacy_token','short_code','guest')),
  secret_hash  BYTEA NOT NULL,
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  created_by   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redeemed_by  UUID REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_tsg_secret ON terminal_session_grants(secret_hash);

-- One live short code per session. Regeneration revokes the old row inside the
-- same transaction, so this index is what makes the swap race-safe.
CREATE UNIQUE INDEX idx_tsg_one_live_code
  ON terminal_session_grants(session_id)
  WHERE kind = 'short_code' AND revoked_at IS NULL;

CREATE INDEX idx_tsg_session ON terminal_session_grants(session_id);

INSERT INTO terminal_session_grants (session_id, kind, secret_hash, created_by)
SELECT id, 'legacy_token', sha256(convert_to(invite_token, 'UTF8')), host_user_id
FROM terminal_sessions
WHERE invite_token IS NOT NULL AND ended_at IS NULL;
