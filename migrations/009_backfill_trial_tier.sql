-- Backfill: set all free non-expired-trial users to pro with a fresh 14-day trial window.
-- Covers accounts created before registration set tier='pro' and trial_ends_at automatically.
UPDATE users
SET subscription_tier = 'pro',
    trial_ends_at = COALESCE(trial_ends_at, now() + interval '14 days')
WHERE subscription_tier = 'free'
  AND trial_used = false;
