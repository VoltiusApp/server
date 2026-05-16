ALTER TABLE users
  ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN email_verified_at TIMESTAMPTZ NULL;

UPDATE users
SET email_verified = TRUE,
    email_verified_at = created_at
WHERE email_verified = FALSE;

CREATE TABLE email_verification_tokens (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token        TEXT NOT NULL UNIQUE DEFAULT replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours',
  consumed_at  TIMESTAMPTZ NULL
);

CREATE INDEX ON email_verification_tokens(token);
CREATE INDEX ON email_verification_tokens(user_id) WHERE consumed_at IS NULL;
