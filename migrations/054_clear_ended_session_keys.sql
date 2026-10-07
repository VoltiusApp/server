UPDATE terminal_sessions SET session_key_bytes = NULL
WHERE ended_at IS NOT NULL AND session_key_bytes IS NOT NULL;
