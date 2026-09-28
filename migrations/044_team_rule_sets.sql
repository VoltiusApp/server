CREATE TABLE team_rule_sets (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID NOT NULL REFERENCES users(id),
    UNIQUE (team_id, id)
);

CREATE TABLE team_rule_set_entries (
    rule_set_id  UUID NOT NULL REFERENCES team_rule_sets(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('everyone', 'role', 'member')),
    subject_id   UUID,
    allow_mask   BIGINT NOT NULL DEFAULT 0,
    deny_mask    BIGINT NOT NULL DEFAULT 0,
    CHECK ((subject_type = 'everyone') = (subject_id IS NULL)),
    CHECK ((allow_mask & deny_mask) = 0)
);
CREATE UNIQUE INDEX team_rule_set_entries_subject
    ON team_rule_set_entries (rule_set_id, subject_type, COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'));

ALTER TABLE team_vault_objects ADD COLUMN rule_set_id UUID;
ALTER TABLE team_vault_objects ADD CONSTRAINT team_vault_objects_rule_set_fk
    FOREIGN KEY (team_id, rule_set_id) REFERENCES team_rule_sets (team_id, id);
CREATE INDEX team_vault_objects_rule_set ON team_vault_objects (team_id, rule_set_id);

ALTER TABLE team_members
    ADD COLUMN last_client_version TEXT NULL,
    ADD COLUMN last_client_rule_sets BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE terminal_sessions ADD COLUMN connection_object_id TEXT NULL;
