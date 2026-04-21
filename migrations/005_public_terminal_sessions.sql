-- Allow terminal sessions without a team (public/direct share)
ALTER TABLE terminal_sessions
    ALTER COLUMN team_id DROP NOT NULL;

-- Store raw session key bytes for public sessions (no E2EE — intentional)
ALTER TABLE terminal_sessions
    ADD COLUMN session_key_bytes TEXT;
