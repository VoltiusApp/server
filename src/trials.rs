use chrono::{DateTime, Duration, Utc};

/// Plan and trial offers a new account starts with.
pub(crate) struct InitialPlan {
    pub tier: &'static str,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub pro_trial_available: bool,
    pub teams_trial_available: bool,
}

pub(crate) fn initial_plan(self_hosted: bool, trial_blocked: bool, supports_activation: bool, now: DateTime<Utc>) -> InitialPlan {
    if self_hosted {
        InitialPlan { tier: "business", trial_ends_at: None, pro_trial_available: false, teams_trial_available: false }
    } else if trial_blocked {
        InitialPlan { tier: "free", trial_ends_at: None, pro_trial_available: false, teams_trial_available: false }
    } else if supports_activation {
        InitialPlan { tier: "free", trial_ends_at: None, pro_trial_available: true, teams_trial_available: true }
    } else {
        InitialPlan { tier: "pro", trial_ends_at: Some(now + Duration::days(14)), pro_trial_available: false, teams_trial_available: true }
    }
}

/// Relaunch statement; must stay identical to the UPDATE in migrations/075_trial_activation.sql.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const RELAUNCH_SQL: &str = "UPDATE users SET pro_trial_available = TRUE, teams_trial_available = TRUE WHERE deleted_at IS NULL AND is_banned = FALSE AND ls_subscription_id IS NULL AND admin_override = FALSE";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::seed_user;

    async fn flags(pool: &sqlx::PgPool, id: uuid::Uuid) -> (bool, bool) {
        sqlx::query_as::<_, (bool, bool)>(
            "SELECT pro_trial_available, teams_trial_available FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn relaunch_marks_only_unpaid_accounts() {
        let pool = crate::test_pool_or_skip!();
        let free = seed_user(&pool).await;
        let paid = seed_user(&pool).await;
        let admin = seed_user(&pool).await;
        let banned = seed_user(&pool).await;
        sqlx::query("UPDATE users SET ls_subscription_id = 'sub_1' WHERE id = $1")
            .bind(paid)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET admin_override = TRUE WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET is_banned = TRUE WHERE id = $1")
            .bind(banned)
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(&format!("{RELAUNCH_SQL} AND id = ANY($1)"))
            .bind(vec![free, paid, admin, banned])
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(flags(&pool, free).await, (true, true));
        assert_eq!(flags(&pool, paid).await, (false, false));
        assert_eq!(flags(&pool, admin).await, (false, false));
        assert_eq!(flags(&pool, banned).await, (false, false));
    }

    #[test]
    fn initial_plan_self_hosted() {
        let p = initial_plan(true, true, true, chrono::Utc::now());
        assert_eq!((p.tier, p.trial_ends_at, p.pro_trial_available, p.teams_trial_available), ("business", None, false, false));
    }

    #[test]
    fn initial_plan_fingerprint_blocked() {
        let p = initial_plan(false, true, true, chrono::Utc::now());
        assert_eq!((p.tier, p.trial_ends_at, p.pro_trial_available, p.teams_trial_available), ("free", None, false, false));
    }

    #[test]
    fn initial_plan_legacy_client() {
        let now = chrono::Utc::now();
        let p = initial_plan(false, false, false, now);
        assert_eq!(p.tier, "pro");
        assert_eq!(p.trial_ends_at, Some(now + chrono::Duration::days(14)));
        assert!(!p.pro_trial_available);
        assert!(p.teams_trial_available);
    }

    #[test]
    fn initial_plan_activation_client() {
        let p = initial_plan(false, false, true, chrono::Utc::now());
        assert_eq!((p.tier, p.trial_ends_at, p.pro_trial_available, p.teams_trial_available), ("free", None, true, true));
    }

    #[test]
    fn relaunch_sql_matches_migration() {
        assert!(include_str!("../migrations/075_trial_activation.sql").contains(RELAUNCH_SQL));
    }
}
