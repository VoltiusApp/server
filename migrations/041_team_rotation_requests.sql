-- Marks a team as owing a rotation after a removal. Cleared implicitly once
-- a rotation lands: requested_at_epoch is always behind the new epoch.
CREATE TABLE team_rotation_requests (
    team_id            UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    requested_at_epoch INTEGER NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, requested_at_epoch)
);
