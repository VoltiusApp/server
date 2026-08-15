-- Every user gets an address that is not their email, so "copy my address"
-- works for a free account without exposing a mailbox. Handles are never
-- recycled: a remembered @kevin must not become a stranger wearing that name.

ALTER TABLE users ADD COLUMN handle TEXT NULL;
ALTER TABLE users ADD COLUMN handle_is_custom BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN handle_updated_at TIMESTAMPTZ NULL;
ALTER TABLE users ADD COLUMN allow_stranger_invites BOOLEAN NOT NULL DEFAULT TRUE;

-- Backfill: same adjective-noun-4digit shape the server generates, retried per
-- row until unique. Deterministic fallback after 10 tries so the migration can
-- never spin on an unlucky namespace.
DO $$
DECLARE
  adjectives TEXT[] := ARRAY['swift','quiet','bright','calm','brave','clever','eager','gentle','happy','jolly',
                             'kind','lively','merry','noble','proud','quick','rapid','sunny','tidy','witty'];
  nouns      TEXT[] := ARRAY['otter','falcon','cedar','harbor','lantern','meadow','nimbus','opal','pebble','quartz',
                             'ridge','sparrow','thistle','umber','violet','willow','yarrow','zephyr','anchor','beacon'];
  r          RECORD;
  candidate  TEXT;
  attempt    INT;
BEGIN
  FOR r IN SELECT id FROM users WHERE handle IS NULL LOOP
    attempt := 0;
    LOOP
      attempt := attempt + 1;
      IF attempt > 10 THEN
        candidate := 'user-' || substr(replace(r.id::text, '-', ''), 1, 12);
      ELSE
        candidate := adjectives[1 + floor(random() * array_length(adjectives, 1))::int]
                     || '-' || nouns[1 + floor(random() * array_length(nouns, 1))::int]
                     || '-' || lpad(floor(random() * 10000)::text, 4, '0');
      END IF;
      EXIT WHEN NOT EXISTS (SELECT 1 FROM users WHERE lower(handle) = candidate);
    END LOOP;
    UPDATE users SET handle = candidate WHERE id = r.id;
  END LOOP;
END $$;

ALTER TABLE users ALTER COLUMN handle SET NOT NULL;
CREATE UNIQUE INDEX idx_users_handle ON users (LOWER(handle));

CREATE TABLE retired_handles (
  handle      TEXT PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  released_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_blocks (
  blocker_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NULL,               -- NULL = permanent
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id)
);

-- NULL until the invitee's WebSocket is first admitted. Drives both the
-- session-name redaction and the "unaccepted stranger" state.
ALTER TABLE terminal_session_invitees ADD COLUMN accepted_at TIMESTAMPTZ NULL;

-- A suppressed knock (blocked or opted-out recipient) writes no grant row —
-- that silence is what makes the block undetectable. This table exists only
-- so the host's own invitee list still shows the stranger as "invited",
-- indistinguishable from a real pending grant; nothing else may read it.
CREATE TABLE suppressed_invites (
  session_id UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, user_id)
);
