-- team_vault_objects.name and .folder_id duplicate fields that already live
-- inside the metadata blob. No server query and no client code reads either
-- column back, so they are pure plaintext leak: connection names and folder
-- grouping readable from any backup or replica without a key.
UPDATE team_vault_objects SET name = NULL, folder_id = NULL;
