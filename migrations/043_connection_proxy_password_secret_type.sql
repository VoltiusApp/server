BEGIN;

ALTER TABLE team_vault_secrets
    DROP CONSTRAINT team_vault_secrets_secret_type_check;

ALTER TABLE team_vault_secrets
    ADD CONSTRAINT team_vault_secrets_secret_type_check CHECK (secret_type IN (
        'connection_password', 'connection_key', 'connection_passphrase',
        'connection_proxy_password',
        'identity_password', 'key_private', 'key_public', 'key_passphrase'
    ));

COMMIT;
