BEGIN;

-- Until delete_object cascaded to team_vault_secrets, removing an object from a
-- team vault left its ciphertext behind, readable by every member with
-- VIEW_SECRETS. Sweep the rows whose object is gone or soft-deleted; nothing
-- reads them, and a member who restores the object republishes its secrets.
DELETE FROM team_vault_secrets s
WHERE NOT EXISTS (
    SELECT 1 FROM team_vault_objects o
    WHERE o.team_id = s.team_id
      AND o.object_id = s.object_id
      AND o.deleted_at IS NULL
);

COMMIT;
