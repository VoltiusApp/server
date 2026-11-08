ALTER TABLE teams
  ADD COLUMN policy JSONB NULL,
  ADD COLUMN policy_revision BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN policy_updated_at TIMESTAMPTZ NULL,
  ADD COLUMN policy_updated_by UUID NULL REFERENCES users(id) ON DELETE SET NULL;

UPDATE teams SET policy = jsonb_build_object('version', 1, 'policy', jsonb_build_object('security.lockTimeoutMinutes', jsonb_build_object('$range', jsonb_build_object('max', lock_max_minutes))) || CASE WHEN lock_force_vault THEN jsonb_build_object('security.lockAction', 'vault') ELSE '{}'::jsonb END), policy_revision = 1 WHERE lock_max_minutes IS NOT NULL AND policy IS NULL;
