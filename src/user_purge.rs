use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const ACTOR: &str = "system";

pub const RELEASED_EMAIL: &str = "id::text || '@purged.invalid'";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PurgeCounts {
    pub deleted: u64,
    pub released: u64,
}

/// Hard-delete users soft-deleted more than `grace_days` ago. A user other rows
/// still reference cannot be deleted, so their email is released instead.
pub async fn purge_expired(pool: &PgPool, grace_days: i64) -> Result<PurgeCounts, sqlx::Error> {
    let expired: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE deleted_at < now() - ($1 * INTERVAL '1 day') ORDER BY deleted_at",
    )
    .bind(grace_days)
    .fetch_all(pool)
    .await?;

    let mut counts = PurgeCounts::default();
    for id in expired {
        match hard_delete(pool, id, grace_days).await {
            Ok(deleted) => counts.deleted += u64::from(deleted),
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23503") => {
                let constraint = e.constraint().unwrap_or("unknown").to_string();
                counts.released += u64::from(release_email(pool, id, grace_days, &constraint).await?);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(counts)
}

async fn hard_delete(pool: &PgPool, id: Uuid, grace_days: i64) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deleted_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "DELETE FROM users WHERE id = $1 AND deleted_at < now() - ($2 * INTERVAL '1 day')
         RETURNING deleted_at",
    )
    .bind(id)
    .bind(grace_days)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(deleted_at) = deleted_at else { return Ok(false) };

    audit(&mut tx, id, "purge_user", json!({ "user_id": id, "deleted_at": deleted_at, "grace_days": grace_days })).await?;
    tx.commit().await?;
    Ok(true)
}

async fn release_email(pool: &PgPool, id: Uuid, grace_days: i64, constraint: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let released = sqlx::query(&format!(
        "UPDATE users SET email = {RELEASED_EMAIL}
         WHERE id = $1 AND deleted_at < now() - ($2 * INTERVAL '1 day') AND email <> {RELEASED_EMAIL}"
    ))
    .bind(id)
    .bind(grace_days)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if !released {
        return Ok(false);
    }

    audit(&mut tx, id, "purge_user_release_email", json!({ "user_id": id, "blocked_by": constraint, "grace_days": grace_days })).await?;
    tx.commit().await?;
    Ok(true)
}

async fn audit(tx: &mut Transaction<'_, Postgres>, id: Uuid, action: &str, detail: Value) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO admin_audit_log (admin_email, target_id, action, detail) VALUES ($1, $2, $3, $4)")
        .bind(ACTOR)
        .bind(id)
        .bind(action)
        .bind(detail)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_team, seed_user};

    const GRACE: i64 = 30;

    async fn soft_delete_days_ago(pool: &PgPool, user: Uuid, days: i64) {
        sqlx::query("UPDATE users SET deleted_at = now() - ($1 * INTERVAL '1 day') WHERE id = $2")
            .bind(days)
            .bind(user)
            .execute(pool)
            .await
            .expect("soft-delete user");
        sqlx::query("INSERT INTO admin_audit_log (admin_email, target_id, action) VALUES ('a@test', $1, 'delete_user_soft')")
            .bind(user)
            .execute(pool)
            .await
            .expect("audit soft delete");
    }

    async fn email_of(pool: &PgPool, user: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user)
            .fetch_optional(pool)
            .await
            .expect("read email")
    }

    async fn audit_count(pool: &PgPool, user: Uuid, action: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_audit_log WHERE target_id = $1 AND action = $2")
            .bind(user)
            .bind(action)
            .fetch_one(pool)
            .await
            .expect("count audit rows")
    }

    async fn register_with_email(pool: &PgPool, email: &str) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, email, account_id, auth_hash, handle) VALUES ($1, $2, $3, 'h', $4)",
        )
        .bind(id)
        .bind(email)
        .bind(Uuid::new_v4())
        .bind(format!("u{}", id.simple()))
        .execute(pool)
        .await?;
        Ok(id)
    }

    #[tokio::test]
    async fn purges_user_past_grace_and_frees_their_email() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let email = email_of(&pool, user).await.unwrap();
        soft_delete_days_ago(&pool, user, GRACE + 1).await;

        purge_expired(&pool, GRACE).await.expect("purge");

        assert_eq!(email_of(&pool, user).await, None, "row is gone");
        assert_eq!(audit_count(&pool, user, "purge_user").await, 1);
        assert_eq!(audit_count(&pool, user, "delete_user_soft").await, 1, "audit trail outlives the user");
        register_with_email(&pool, &email.to_uppercase()).await.expect("email is free again");
    }

    #[tokio::test]
    async fn keeps_live_users_and_users_within_grace() {
        let pool = test_pool_or_skip!();
        let live = seed_user(&pool).await;
        let recent = seed_user(&pool).await;
        soft_delete_days_ago(&pool, recent, GRACE - 1).await;

        purge_expired(&pool, GRACE).await.expect("purge");

        assert!(email_of(&pool, live).await.is_some());
        let email = email_of(&pool, recent).await.expect("recently deleted user kept");
        assert!(register_with_email(&pool, &email).await.is_err(), "email stays reserved during grace");
    }

    #[tokio::test]
    async fn releases_email_when_references_block_the_delete() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        seed_team(&pool, owner).await;
        let email = email_of(&pool, owner).await.unwrap();
        soft_delete_days_ago(&pool, owner, GRACE + 1).await;

        purge_expired(&pool, GRACE).await.expect("purge");
        purge_expired(&pool, GRACE).await.expect("second purge");

        assert_eq!(email_of(&pool, owner).await, Some(format!("{owner}@purged.invalid")));
        assert_eq!(audit_count(&pool, owner, "purge_user_release_email").await, 1, "released once");
        register_with_email(&pool, &email).await.expect("email is free again");
    }
}
