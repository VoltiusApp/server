//! Single source of truth for the tier a user is actually entitled to *right now*.
//!
//! A trial is represented by `trial_ends_at` being set on a non-free tier. When
//! that timestamp passes the user reverts to `free` — there is no paid
//! subscription to keep them on the paid tier. Paid accounts have
//! `trial_ends_at = NULL` (the LemonSqueezy webhook clears it on activation), so
//! they are never affected. Admin-comped accounts (`admin_override`) and accounts
//! with an active paid subscription are always left untouched.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Returns the effective tier: `"free"` if this is an expired trial, otherwise
/// the stored tier unchanged. Borrows `stored_tier` for the non-expired case.
pub fn effective_tier(
    stored_tier: &str,
    trial_ends_at: Option<DateTime<Utc>>,
    has_paid_sub: bool,
    admin_override: bool,
    now: DateTime<Utc>,
) -> &str {
    if stored_tier != "free" && !admin_override && !has_paid_sub {
        if let Some(ends) = trial_ends_at {
            if ends <= now {
                return "free";
            }
        }
    }
    stored_tier
}

/// [`effective_tier`] for one account, read from the database. Every tier gate
/// outside `/v1/auth/me` must go through this rather than comparing
/// `users.subscription_tier`: an expired trial still stores `'pro'` there, so a
/// direct comparison hands a lapsed account a paid feature.
///
/// Falls back to `"free"` if the row can't be read — a gate that fails open is
/// the bug this function exists to prevent.
pub async fn effective_tier_for_user(pool: &PgPool, user_id: uuid::Uuid) -> String {
    match sqlx::query_as::<_, (String, Option<DateTime<Utc>>, bool, Option<String>)>(
        "SELECT subscription_tier, trial_ends_at, admin_override, ls_subscription_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    {
        Ok((tier, trial_ends_at, admin_override, ls_subscription_id)) => effective_tier(
            &tier,
            trial_ends_at,
            ls_subscription_id.is_some(),
            admin_override,
            Utc::now(),
        )
        .to_string(),
        Err(_) => "free".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_777_680_000, 0).unwrap()
    }

    #[test]
    fn expired_trial_reverts_to_free() {
        let ends = now() - Duration::seconds(1);
        assert_eq!(effective_tier("pro", Some(ends), false, false, now()), "free");
    }

    #[test]
    fn active_trial_keeps_tier() {
        let ends = now() + Duration::days(3);
        assert_eq!(effective_tier("pro", Some(ends), false, false, now()), "pro");
    }

    #[test]
    fn trial_ending_exactly_now_is_expired() {
        assert_eq!(effective_tier("pro", Some(now()), false, false, now()), "free");
    }

    #[test]
    fn paid_account_has_no_trial_timestamp_and_stays() {
        // Paid users carry trial_ends_at = NULL.
        assert_eq!(effective_tier("pro", None, true, false, now()), "pro");
    }

    #[test]
    fn paid_sub_survives_even_with_stale_trial_timestamp() {
        let ends = now() - Duration::days(30);
        assert_eq!(effective_tier("pro", Some(ends), true, false, now()), "pro");
    }

    #[test]
    fn admin_override_survives_expired_trial() {
        let ends = now() - Duration::days(30);
        assert_eq!(effective_tier("pro", Some(ends), false, true, now()), "pro");
    }

    #[test]
    fn free_stays_free() {
        assert_eq!(effective_tier("free", None, false, false, now()), "free");
    }

    #[test]
    fn expired_teams_trial_reverts_to_free() {
        let ends = now() - Duration::seconds(1);
        assert_eq!(effective_tier("business", Some(ends), false, false, now()), "free");
    }
}
