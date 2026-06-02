CREATE TABLE mobile_waitlist_signups (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT NOT NULL,
  platform    TEXT NOT NULL CHECK (platform IN ('android', 'ios')),
  source      TEXT NOT NULL DEFAULT 'landing-download',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX mobile_waitlist_signups_email_platform_key
  ON mobile_waitlist_signups (lower(email), platform);

CREATE INDEX mobile_waitlist_signups_created_at_idx
  ON mobile_waitlist_signups (created_at DESC);
