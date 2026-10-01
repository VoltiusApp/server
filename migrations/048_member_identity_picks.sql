CREATE TABLE member_identity_picks (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    object_id   TEXT,
    team_id     UUID,
    identity_id TEXT NOT NULL CHECK (length(identity_id) BETWEEN 1 AND 128),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((object_id IS NULL) <> (team_id IS NULL)),
    FOREIGN KEY (team_id, user_id) REFERENCES team_members(team_id, user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX member_identity_picks_object ON member_identity_picks (user_id, object_id) WHERE object_id IS NOT NULL;
CREATE UNIQUE INDEX member_identity_picks_default ON member_identity_picks (user_id, team_id) WHERE team_id IS NOT NULL;
