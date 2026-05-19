BEGIN;

CREATE TABLE team_user_object_prefs (
    team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    object_id  TEXT NOT NULL,
    pinned     BOOLEAN,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id, object_id)
);

CREATE INDEX idx_team_user_prefs_user ON team_user_object_prefs(team_id, user_id);

-- Backfill: every team-vault object currently flagged pinned/favorited becomes
-- a personal pin for the user who last touched it. metadata.pinned stays as
-- the team default so other members continue to see the same items pinned.
INSERT INTO team_user_object_prefs (team_id, user_id, object_id, pinned)
SELECT team_id, updated_by, object_id, true
FROM team_vault_objects
WHERE deleted_at IS NULL
  AND (
    (object_type <> 'snippet' AND COALESCE((metadata ->> 'pinned')::boolean, false))
    OR
    (object_type = 'snippet' AND COALESCE((metadata ->> 'favorite')::boolean, false))
  )
ON CONFLICT (team_id, user_id, object_id) DO NOTHING;

COMMIT;
