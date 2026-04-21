-- Multi-vault support: a session can be shared with members of multiple vaults
CREATE TABLE terminal_session_vaults (
    session_id  UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    PRIMARY KEY (session_id, team_id)
);

CREATE INDEX idx_tsv_team ON terminal_session_vaults(team_id);

-- Role filter: if non-empty, only members with one of these roles can join
-- Uses team_members.role TEXT values: 'owner', 'manager', 'editor', 'member'
ALTER TABLE terminal_sessions ADD COLUMN allowed_roles TEXT[] NOT NULL DEFAULT '{}';

-- Invite link token: set for invite_link visibility sessions
ALTER TABLE terminal_sessions ADD COLUMN invite_token TEXT UNIQUE;
