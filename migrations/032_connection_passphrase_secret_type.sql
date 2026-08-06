BEGIN;

-- A connection can carry an inline private key (`key:<conn_id>`) that is itself
-- passphrase-encrypted, and that passphrase is stored locally under
-- `passphrase:<conn_id>`. It had no `secret_type`, so publishing it to a team
-- vault hit this CHECK and the client — which swallows publish errors — showed
-- nothing. Members received the encrypted key without the passphrase needed to
-- use it.
--
-- Keys held in the keychain were never affected: their passphrase already had
-- `key_passphrase` (`key:<key_id>:passphrase`). This adds the connection-scoped
-- counterpart only.
ALTER TABLE team_vault_secrets
    DROP CONSTRAINT team_vault_secrets_secret_type_check;

ALTER TABLE team_vault_secrets
    ADD CONSTRAINT team_vault_secrets_secret_type_check CHECK (secret_type IN (
        'connection_password', 'connection_key', 'connection_passphrase',
        'identity_password', 'key_private', 'key_public', 'key_passphrase'
    ));

COMMIT;
