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
    fn relaunch_sql_matches_migration() {
        assert!(include_str!("../migrations/075_trial_activation.sql").contains(RELAUNCH_SQL));
    }
}
