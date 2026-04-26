-- Migration 017: Discord-style many-to-many roles
-- Replaces custom_roles + team_members.role with team_roles + team_member_roles

-- 1. New unified roles table (builtin + custom)
CREATE TABLE team_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    color       TEXT,
    permissions BIGINT NOT NULL DEFAULT 0,
    is_builtin  BOOLEAN NOT NULL DEFAULT FALSE,
    position    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, name)
);
CREATE INDEX idx_team_roles_team ON team_roles(team_id);

-- 2. Many-to-many join table
CREATE TABLE team_member_roles (
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES team_roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id, role_id)
);
CREATE INDEX idx_tmr_user ON team_member_roles(user_id);
CREATE INDEX idx_tmr_role ON team_member_roles(role_id);

-- 3. Seed builtin roles for every existing team
-- owner=65535(0xFFFF), manager=63487, editor=28799, member=28679, connect-only=28676
INSERT INTO team_roles (team_id, name, permissions, is_builtin, position)
SELECT id, 'owner',        65535, TRUE, 0 FROM teams
UNION ALL
SELECT id, 'manager',      63487, TRUE, 1 FROM teams
UNION ALL
SELECT id, 'editor',       28799, TRUE, 2 FROM teams
UNION ALL
SELECT id, 'member',       28679, TRUE, 3 FROM teams
UNION ALL
SELECT id, 'connect-only', 28676, TRUE, 4 FROM teams;

-- 4. Migrate existing custom_roles → team_roles (is_builtin=false)
INSERT INTO team_roles (id, team_id, name, permissions, is_builtin, position, created_at)
SELECT id, team_id, name, permissions, FALSE, 10, created_at
FROM custom_roles;

-- 5a. Members with a custom role: assign that custom role
INSERT INTO team_member_roles (team_id, user_id, role_id, assigned_at)
SELECT tm.team_id, tm.user_id, tm.custom_role_id, tm.joined_at
FROM team_members tm
WHERE tm.custom_role_id IS NOT NULL;

-- 5b. All members: assign their builtin role
INSERT INTO team_member_roles (team_id, user_id, role_id, assigned_at)
SELECT tm.team_id, tm.user_id, tr.id, tm.joined_at
FROM team_members tm
JOIN team_roles tr ON tr.team_id = tm.team_id
    AND tr.name = tm.role
    AND tr.is_builtin = TRUE;

-- 6. Drop old role columns from team_members
ALTER TABLE team_members DROP COLUMN role;
ALTER TABLE team_members DROP COLUMN custom_role_id;

-- 7. Drop old custom_roles table (data migrated to team_roles)
DROP TABLE custom_roles;
