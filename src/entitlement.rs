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
use uuid::Uuid;

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

pub const OWNER_PLAN_COLUMNS: &str =
    "u.subscription_tier, u.trial_ends_at, u.admin_override, u.ls_subscription_id";

pub type TierRow = (String, Option<DateTime<Utc>>, bool, Option<String>);

pub fn effective_tier_of(row: &TierRow) -> String {
    effective_tier(&row.0, row.1, row.3.is_some(), row.2, Utc::now()).to_string()
}

/// [`effective_tier`] for one account, read from the database. Every tier gate
/// outside `/v1/auth/me` must go through this rather than comparing
/// `users.subscription_tier`: an expired trial still stores `'pro'` there, so a
/// direct comparison hands a lapsed account a paid feature.
///
/// Falls back to `"free"` if the row can't be read — a gate that fails open is
/// the bug this function exists to prevent.
pub async fn effective_tier_for_user(pool: &PgPool, user_id: uuid::Uuid) -> String {
    match sqlx::query_as::<_, TierRow>(&format!(
        "SELECT {OWNER_PLAN_COLUMNS} FROM users u WHERE u.id = $1"
    ))
    .bind(user_id)
    .fetch_one(pool)
    .await
    {
        Ok(row) => effective_tier_of(&row),
        Err(_) => "free".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatPlan {
    pub tier: String,
    pub team_id: Uuid,
    pub team_name: String,
    pub trial: bool,
}

fn tier_rank(tier: &str) -> u8 {
    match tier {
        "business" => 3,
        "teams" => 2,
        "pro" => 1,
        _ => 0,
    }
}

pub fn seat_upgrade(own: &str, seat: Option<SeatPlan>) -> Option<SeatPlan> {
    seat.filter(|s| tier_rank(&s.tier) > tier_rank(own))
}

type SeatRow = (
    Uuid,
    String,
    String,
    Option<DateTime<Utc>>,
    bool,
    Option<String>,
    Option<String>,
);

pub async fn seat_plan_for_user(pool: &PgPool, user_id: Uuid) -> Option<SeatPlan> {
    if crate::self_host::is_self_hosted() {
        return None;
    }
    let rows = sqlx::query_as::<_, SeatRow>(&format!(
        "SELECT t.id, t.name, {OWNER_PLAN_COLUMNS}, u.ls_subscription_status \
         FROM team_members tm \
         JOIN teams t ON t.id = tm.team_id \
         JOIN users u ON u.id = t.owner_id \
         WHERE tm.user_id = $1 AND t.owner_id <> $1 \
         ORDER BY t.id"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
    .ok()?;
    let now = Utc::now();
    let mut best: Option<SeatPlan> = None;
    for (team_id, team_name, stored, trial_ends_at, admin_override, ls_id, ls_status) in rows {
        let tier = effective_tier(&stored, trial_ends_at, ls_id.is_some(), admin_override, now);
        if tier != "teams" && tier != "business" {
            continue;
        }
        if best
            .as_ref()
            .is_some_and(|b| tier_rank(tier) <= tier_rank(&b.tier))
        {
            continue;
        }
        best = Some(SeatPlan {
            tier: tier.to_string(),
            team_id,
            team_name,
            trial: ls_status.as_deref() == Some("on_trial")
                || (trial_ends_at.is_some() && ls_id.is_none() && !admin_override),
        });
    }
    best
}

pub async fn benefit_tier_for_user(pool: &PgPool, user_id: Uuid) -> String {
    let own = effective_tier_for_user(pool, user_id).await;
    match seat_upgrade(&own, seat_plan_for_user(pool, user_id).await) {
        Some(seat) => seat.tier,
        None => own,
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

    use crate::test_support::{
        add_member, seed_team, seed_user, set_user_ls_status, set_user_tier, set_user_trial,
        BillingMode,
    };

    async fn owner_with(pool: &PgPool, tier: &str) -> Uuid {
        let owner = seed_user(pool).await;
        set_user_tier(pool, owner, tier).await;
        owner
    }

    async fn team_of(pool: &PgPool, owner: Uuid, members: &[Uuid]) -> Uuid {
        let team = seed_team(pool, owner).await;
        add_member(pool, team, owner).await;
        for m in members {
            add_member(pool, team, *m).await;
        }
        team
    }

    #[test]
    fn seat_upgrade_only_when_strictly_better() {
        let seat = |tier: &str| SeatPlan {
            tier: tier.to_string(),
            team_id: Uuid::nil(),
            team_name: String::new(),
            trial: false,
        };
        assert!(seat_upgrade("free", Some(seat("teams"))).is_some());
        assert!(seat_upgrade("pro", Some(seat("teams"))).is_some());
        assert!(seat_upgrade("teams", Some(seat("teams"))).is_none());
        assert!(seat_upgrade("business", Some(seat("teams"))).is_none());
        assert!(seat_upgrade("free", None).is_none());
    }

    #[tokio::test]
    async fn seat_plan_ignores_pro_and_free_owners() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = seed_user(&pool).await;
        for tier in ["free", "pro"] {
            let owner = owner_with(&pool, tier).await;
            team_of(&pool, owner, &[member]).await;
        }
        assert_eq!(seat_plan_for_user(&pool, member).await, None);
        assert_eq!(benefit_tier_for_user(&pool, member).await, "free");
    }

    #[tokio::test]
    async fn seat_plan_ignores_teams_the_user_owns() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let owner = owner_with(&pool, "business").await;
        team_of(&pool, owner, &[]).await;
        assert_eq!(seat_plan_for_user(&pool, owner).await, None);
    }

    #[tokio::test]
    async fn seat_plan_picks_business_over_teams() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = seed_user(&pool).await;
        let teams_owner = owner_with(&pool, "teams").await;
        let biz_owner = owner_with(&pool, "business").await;
        team_of(&pool, teams_owner, &[member]).await;
        let biz_team = team_of(&pool, biz_owner, &[member]).await;
        let plan = seat_plan_for_user(&pool, member).await.unwrap();
        assert_eq!(plan.tier, "business");
        assert_eq!(plan.team_id, biz_team);
        assert_eq!(plan.team_name, "test-team");
        assert!(!plan.trial);
    }

    #[tokio::test]
    async fn seat_plan_ties_pick_lowest_team_id() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = seed_user(&pool).await;
        let a = team_of(&pool, owner_with(&pool, "teams").await, &[member]).await;
        let b = team_of(&pool, owner_with(&pool, "teams").await, &[member]).await;
        let plan = seat_plan_for_user(&pool, member).await.unwrap();
        assert_eq!(plan.team_id, a.min(b));
    }

    #[tokio::test]
    async fn seat_plan_flags_trial_owner() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = seed_user(&pool).await;
        let owner = owner_with(&pool, "teams").await;
        set_user_trial(&pool, owner, 5).await;
        team_of(&pool, owner, &[member]).await;
        let plan = seat_plan_for_user(&pool, member).await.unwrap();
        assert!(plan.trial);

        let member2 = seed_user(&pool).await;
        let owner2 = owner_with(&pool, "teams").await;
        set_user_ls_status(&pool, owner2, "on_trial").await;
        team_of(&pool, owner2, &[member2]).await;
        assert!(seat_plan_for_user(&pool, member2).await.unwrap().trial);
    }

    #[tokio::test]
    async fn seat_plan_comped_owner_is_not_a_trial() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = seed_user(&pool).await;
        let owner = owner_with(&pool, "teams").await;
        set_user_trial(&pool, owner, 5).await;
        sqlx::query("UPDATE users SET admin_override = true WHERE id = $1")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        team_of(&pool, owner, &[member]).await;
        assert!(!seat_plan_for_user(&pool, member).await.unwrap().trial);
    }

    #[tokio::test]
    async fn seat_plan_none_when_owner_trial_expired() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = seed_user(&pool).await;
        let owner = owner_with(&pool, "business").await;
        set_user_trial(&pool, owner, -1).await;
        team_of(&pool, owner, &[member]).await;
        assert_eq!(seat_plan_for_user(&pool, member).await, None);
    }

    #[tokio::test]
    async fn seat_plan_none_when_self_hosted() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::self_hosted();
        let member = seed_user(&pool).await;
        team_of(&pool, owner_with(&pool, "business").await, &[member]).await;
        assert_eq!(seat_plan_for_user(&pool, member).await, None);
    }

    #[tokio::test]
    async fn benefit_tier_keeps_own_business_over_teams_seat() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = owner_with(&pool, "business").await;
        team_of(&pool, owner_with(&pool, "teams").await, &[member]).await;
        assert_eq!(benefit_tier_for_user(&pool, member).await, "business");
    }

    #[tokio::test]
    async fn benefit_tier_lifts_pro_to_seat_tier() {
        let pool = crate::test_pool_or_skip!();
        let _mode = BillingMode::hosted();
        let member = owner_with(&pool, "pro").await;
        team_of(&pool, owner_with(&pool, "teams").await, &[member]).await;
        assert_eq!(benefit_tier_for_user(&pool, member).await, "teams");
    }
}
