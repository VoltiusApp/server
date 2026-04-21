-- Custom roles per team (Phase 4)
CREATE TABLE custom_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    permissions BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, name)
);

CREATE INDEX idx_custom_roles_team ON custom_roles(team_id);

-- Assign a custom role to a team member (optional; NULL = built-in role)
ALTER TABLE team_members
    ADD COLUMN custom_role_id UUID REFERENCES custom_roles(id) ON DELETE SET NULL;
