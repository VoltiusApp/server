-- Who was admitted to an invite_link session, and by which grant: the host may
-- wrap the session key only for a user whose admitting grant is still live.
CREATE TABLE terminal_session_link_guests (
  session_id  UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grant_id    UUID NOT NULL REFERENCES terminal_session_grants(id) ON DELETE CASCADE,
  PRIMARY KEY (session_id, user_id)
);
