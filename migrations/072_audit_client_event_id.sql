ALTER TABLE audit_logs ADD COLUMN client_event_id UUID;

CREATE UNIQUE INDEX audit_logs_client_event_id_idx
    ON audit_logs (team_id, actor_id, client_event_id)
    WHERE client_event_id IS NOT NULL;
