ALTER TABLE teams ADD COLUMN seat_plan TEXT NOT NULL DEFAULT 'free';

UPDATE teams t SET seat_plan = u.subscription_tier
  FROM users u
 WHERE u.id = t.owner_id
   AND u.subscription_tier IN ('teams', 'business')
   AND (u.admin_override OR u.ls_subscription_id IS NOT NULL
        OR u.trial_ends_at IS NULL OR u.trial_ends_at > now());
