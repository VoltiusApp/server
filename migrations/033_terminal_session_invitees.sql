CREATE TABLE terminal_session_invitees (
  session_id UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, user_id)
);
CREATE INDEX idx_tsi_user ON terminal_session_invitees(user_id);
