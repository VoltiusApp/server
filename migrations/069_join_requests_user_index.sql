CREATE INDEX IF NOT EXISTS team_join_requests_user_team_created ON team_join_requests (user_id, team_id, created_at DESC);
