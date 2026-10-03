-- Nothing reads or writes these since #82 (#63). Deploy only after a binary
-- without them is the rollback target: older binaries select them in list_members.
ALTER TABLE team_members
    DROP COLUMN IF EXISTS last_client_version,
    DROP COLUMN IF EXISTS last_client_rule_sets;
