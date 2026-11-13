-- Trial activation: per-account trial availability, last ended plan, promo history.
ALTER TABLE users ADD COLUMN IF NOT EXISTS pro_trial_available BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS teams_trial_available BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_plan_ended_at TIMESTAMPTZ NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_plan_ended_kind TEXT NULL
    CHECK (last_plan_ended_kind IN ('pro_trial', 'teams_trial', 'subscription'));

CREATE TABLE IF NOT EXISTS promo_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    promo       TEXT NOT NULL CHECK (promo IN ('pro_redeem', 'teams_promo', 'plan_ended')),
    event       TEXT NOT NULL CHECK (event IN ('shown', 'dismissed', 'clicked', 'activated')),
    source      TEXT NOT NULL DEFAULT 'launch',
    occurrence  TIMESTAMPTZ NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_promo_events_user_promo ON promo_events (user_id, promo);

CREATE UNIQUE INDEX IF NOT EXISTS idx_promo_events_shown_once
    ON promo_events (user_id, promo, COALESCE(occurrence, 'epoch'::timestamptz))
    WHERE event = 'shown';

-- Relaunch: offer both trials to every unpaid, active account.
UPDATE users SET pro_trial_available = TRUE, teams_trial_available = TRUE WHERE deleted_at IS NULL AND is_banned = FALSE AND ls_subscription_id IS NULL AND admin_override = FALSE;
