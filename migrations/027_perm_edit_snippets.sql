BEGIN;

-- Grant PERM_EDIT_SNIPPETS (bit 16 = 65536) to every role row that already has
-- PERM_EDIT_CONNECTIONS (bit 3 = 8). Covers builtin roles AND any custom roles
-- users created so the split is a zero-loss refactor.
UPDATE team_roles
SET permissions = permissions | 65536
WHERE (permissions & 8) <> 0;

COMMIT;
