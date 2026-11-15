-- Count every paywall opening: only the launch `shown` is deduplicated per promo and occurrence.
DROP INDEX IF EXISTS idx_promo_events_shown_once;

CREATE UNIQUE INDEX IF NOT EXISTS idx_promo_events_shown_once
    ON promo_events (user_id, promo, COALESCE(occurrence, 'epoch'::timestamptz))
    WHERE event = 'shown' AND source = 'launch';
