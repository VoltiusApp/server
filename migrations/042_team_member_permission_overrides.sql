CREATE TABLE team_member_permission_overrides (
    team_id    UUID NOT NULL,
    user_id    UUID NOT NULL,
    allow_mask BIGINT NOT NULL DEFAULT 0,
    deny_mask  BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID NOT NULL REFERENCES users(id),
    PRIMARY KEY (team_id, user_id),
    FOREIGN KEY (team_id, user_id)
        REFERENCES team_members(team_id, user_id) ON DELETE CASCADE
);
