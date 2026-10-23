-- Deleting a user (self-service `DELETE /v1/auth/account`, or the admin hard
-- delete) failed with a foreign-key error for anyone who had ever touched a
-- team: these references to users(id) had no ON DELETE rule, or RESTRICT.

-- Authorship and history: the row belongs to the team and outlives the person.
-- The column goes NULL ("someone who has since deleted their account").
ALTER TABLE audit_logs
    ALTER COLUMN actor_id DROP NOT NULL,
    DROP CONSTRAINT audit_logs_actor_id_fkey,
    ADD CONSTRAINT audit_logs_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_vault_objects
    ALTER COLUMN updated_by DROP NOT NULL,
    DROP CONSTRAINT team_vault_objects_updated_by_fkey,
    ADD CONSTRAINT team_vault_objects_updated_by_fkey
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_vault_secrets
    ALTER COLUMN updated_by DROP NOT NULL,
    DROP CONSTRAINT team_vault_secrets_updated_by_fkey,
    ADD CONSTRAINT team_vault_secrets_updated_by_fkey
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_sync_blobs
    ALTER COLUMN updated_by DROP NOT NULL,
    DROP CONSTRAINT team_sync_blobs_updated_by_fkey,
    ADD CONSTRAINT team_sync_blobs_updated_by_fkey
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_rule_sets
    ALTER COLUMN updated_by DROP NOT NULL,
    DROP CONSTRAINT team_rule_sets_updated_by_fkey,
    ADD CONSTRAINT team_rule_sets_updated_by_fkey
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_member_permission_overrides
    ALTER COLUMN updated_by DROP NOT NULL,
    DROP CONSTRAINT team_member_permission_overrides_updated_by_fkey,
    ADD CONSTRAINT team_member_permission_overrides_updated_by_fkey
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_key_epochs
    ALTER COLUMN created_by DROP NOT NULL,
    DROP CONSTRAINT team_key_epochs_created_by_fkey,
    ADD CONSTRAINT team_key_epochs_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

-- Already nullable.
ALTER TABLE team_members
    DROP CONSTRAINT team_members_invited_by_fkey,
    ADD CONSTRAINT team_members_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE admin_audit_log
    DROP CONSTRAINT admin_audit_log_target_id_fkey,
    ADD CONSTRAINT admin_audit_log_target_id_fkey
        FOREIGN KEY (target_id) REFERENCES users(id) ON DELETE SET NULL;

-- A terminal session cannot exist without its host; everything hanging off it
-- (keys, vaults, invitees, grants) already cascades from terminal_sessions.
ALTER TABLE terminal_sessions
    DROP CONSTRAINT terminal_sessions_host_user_id_fkey,
    ADD CONSTRAINT terminal_sessions_host_user_id_fkey
        FOREIGN KEY (host_user_id) REFERENCES users(id) ON DELETE CASCADE;

-- team_vault_keys.wrapped_by is not authorship, it is key material: a member
-- unwraps their copy of the team key with the *wrapper's* X25519 public key,
-- fetched by id from GET /v1/users/:id/public-key. NULLing it, or deleting the
-- wraps a departed member made, would leave every member they distributed the
-- key to (current or historical epoch) unable to decrypt the team vault. So the
-- id stays, the FK goes, and the departed wrapper's public key is kept here for
-- as long as one of their wraps does. A public key is not a secret and, once the
-- user row is gone, is tied to nothing but a random id.
ALTER TABLE team_vault_keys DROP CONSTRAINT team_vault_keys_wrapped_by_fkey;

CREATE TABLE retired_user_keys (
    user_id    UUID PRIMARY KEY,
    public_key TEXT NOT NULL,
    retired_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- teams.owner_id stays RESTRICT on purpose: deleting an owner must decide what
-- happens to the team first (see routes::auth::delete_account).
