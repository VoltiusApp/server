//! Once-per-day liveness stamping for `users.last_seen_on`.
//!
//! The column is a coarse "this account is still in use" signal, used for
//! dormant-account detection and monthly-active counts. It is a DATE that is
//! overwritten in place: no history accumulates, and nothing about *what* a user
//! did is recorded. See `migrations/031_user_last_seen.sql`.
//!
//! Call sites use [`touch`], which spawns the write and returns immediately, so
//! handlers never pay for it and never fail because of it.

use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

/// Stamp `user_id` as seen today. Returns the number of rows written, so callers
/// (and tests) can tell a real write from a same-day no-op.
///
/// The `IS DISTINCT FROM` guard makes this at most one write per user per day —
/// repeat calls match no rows and cost a single primary-key lookup.
pub async fn stamp(pool: &PgPool, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE users SET last_seen_on = current_date
         WHERE id = $1 AND last_seen_on IS DISTINCT FROM current_date",
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Whole-table activity rollup for the admin overview.
///
/// `never_seen` is the honest counterpart to the active counts: until every
/// account has reconnected at least once after this column shipped, some of it
/// is "not yet stamped" rather than "dormant", and the two must not be confused.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct ActivityCounts {
    pub active_7d: i64,
    pub active_30d: i64,
    pub never_seen: i64,
}

/// Count live accounts by recency of last use. Windows are inclusive of today,
/// so `active_7d` spans today and the six days before it.
pub async fn activity_counts(pool: &PgPool) -> Result<ActivityCounts, sqlx::Error> {
    let (active_7d, active_30d, never_seen) = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE last_seen_on > current_date - 7),
            COUNT(*) FILTER (WHERE last_seen_on > current_date - 30),
            COUNT(*) FILTER (WHERE last_seen_on IS NULL)
        FROM users
        WHERE deleted_at IS NULL
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(ActivityCounts { active_7d, active_30d, never_seen })
}

/// Fire-and-forget [`stamp`]. Liveness is best-effort bookkeeping: it must never
/// add latency to a request or turn a working endpoint into a failing one, so
/// the write runs on its own task and a failure is logged and dropped.
pub fn touch(pool: &PgPool, user_id: Uuid) {
    let pool = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = stamp(&pool, user_id).await {
            warn!(error = %e, user_id = %user_id, "Failed to stamp last_seen_on");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{last_seen_lock, seed_user};
    use chrono::NaiveDate;

    /// Age a seeded user by setting `last_seen_on` to N days ago.
    async fn set_last_seen_days_ago(pool: &PgPool, user_id: Uuid, days: i32) {
        sqlx::query("UPDATE users SET last_seen_on = current_date - $1 WHERE id = $2")
            .bind(days)
            .bind(user_id)
            .execute(pool)
            .await
            .expect("age last_seen_on");
    }

    async fn last_seen_on(pool: &PgPool, user_id: Uuid) -> Option<NaiveDate> {
        sqlx::query_scalar::<_, Option<NaiveDate>>(
            "SELECT last_seen_on FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read last_seen_on")
    }

    #[tokio::test]
    async fn activity_counts_bucket_users_by_recency() {
        let _guard = last_seen_lock();
        let pool = test_pool_or_skip!();
        let before = activity_counts(&pool).await.expect("baseline counts");

        let today = seed_user(&pool).await;
        set_last_seen_days_ago(&pool, today, 0).await;
        let last_week = seed_user(&pool).await;
        set_last_seen_days_ago(&pool, last_week, 10).await;
        let long_ago = seed_user(&pool).await;
        set_last_seen_days_ago(&pool, long_ago, 400).await;
        let _unseen = seed_user(&pool).await; // last_seen_on stays NULL

        let after = activity_counts(&pool).await.expect("counts");

        assert_eq!(after.active_7d - before.active_7d, 1, "only today's user is 7d-active");
        assert_eq!(
            after.active_30d - before.active_30d,
            2,
            "today + 10-days-ago are 30d-active; 400-days-ago is not"
        );
        assert_eq!(
            after.never_seen - before.never_seen,
            1,
            "the unstamped user counts as never seen, the 400-day one does not"
        );
    }

    #[tokio::test]
    async fn activity_counts_excludes_soft_deleted_users() {
        let _guard = last_seen_lock();
        let pool = test_pool_or_skip!();
        let before = activity_counts(&pool).await.expect("baseline counts");

        let user = seed_user(&pool).await;
        set_last_seen_days_ago(&pool, user, 0).await;
        sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .expect("soft-delete user");

        let after = activity_counts(&pool).await.expect("counts");

        assert_eq!(after.active_7d, before.active_7d, "soft-deleted users are not active");
    }

    #[tokio::test]
    async fn stamp_marks_a_never_seen_user_as_seen_today() {
        let _guard = last_seen_lock();
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        assert_eq!(last_seen_on(&pool, user).await, None, "fresh user starts unseen");

        stamp(&pool, user).await.expect("stamp");

        let today: NaiveDate = sqlx::query_scalar("SELECT current_date")
            .fetch_one(&pool)
            .await
            .expect("current_date");
        assert_eq!(last_seen_on(&pool, user).await, Some(today));
    }

    #[tokio::test]
    async fn stamp_is_a_no_op_when_already_seen_today() {
        let _guard = last_seen_lock();
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        assert_eq!(stamp(&pool, user).await.expect("first stamp"), 1);
        assert_eq!(
            stamp(&pool, user).await.expect("second stamp"),
            0,
            "same-day stamp must not write again"
        );
    }

    #[tokio::test]
    async fn stamp_advances_a_stale_date() {
        let _guard = last_seen_lock();
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        sqlx::query("UPDATE users SET last_seen_on = current_date - 400 WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .expect("age the user");

        assert_eq!(stamp(&pool, user).await.expect("stamp"), 1);

        let today: NaiveDate = sqlx::query_scalar("SELECT current_date")
            .fetch_one(&pool)
            .await
            .expect("current_date");
        assert_eq!(last_seen_on(&pool, user).await, Some(today));
    }
}
