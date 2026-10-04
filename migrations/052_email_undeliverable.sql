-- Set by the Resend webhook when mail to the address hard-bounces or is suppressed.
ALTER TABLE users ADD COLUMN email_undeliverable_at TIMESTAMPTZ;
