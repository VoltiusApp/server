use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{error, info};

/// Ignores applied versions this build lacks, so a rollback to an older image still boots.
pub(crate) fn migrator() -> Migrator {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator
}

pub async fn create_pool() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    info!("Initializing PostgreSQL connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .unwrap_or_else(|err| {
            error!(error = %err, "Failed to connect to database");
            panic!("Failed to connect to database");
        });

    info!("PostgreSQL connection pool is ready");

    migrator()
        .run(&pool)
        .await
        .unwrap_or_else(|err| {
            error!(error = %err, "Failed to run migrations");
            panic!("Failed to run migrations");
        });
    info!("Migrations applied successfully");

    reconcile_legacy_grants(&pool).await;
    backfill_team_policies(&pool).await;

    pool
}

pub(crate) async fn backfill_team_policies(pool: &PgPool) {
    match sqlx::query(crate::team_policy::LOCK_POLICY_BACKFILL)
        .execute(pool)
        .await
    {
        Ok(res) => info!(filled = res.rows_affected(), "Backfilled team policy documents"),
        Err(err) => error!(error = %err, "Failed to backfill team policy documents"),
    }
}

/// Migration 037's backfill is one-shot: a rollback-then-forward-again cycle
/// can leave live invite_link sessions with an `invite_token` but no grant,
/// since nothing reads that column outside the grants path any more. Runs
/// every boot and is idempotent — the anti-join only ever inserts missing rows.
/// ON CONFLICT DO NOTHING on idx_tsg_secret: a rolling deploy can start two
/// instances close enough together that their anti-joins both see the same
/// orphan under READ COMMITTED; the loser must not crash the boot.
async fn reconcile_legacy_grants(pool: &PgPool) {
    let result = sqlx::query(
        "INSERT INTO terminal_session_grants (session_id, kind, secret_hash, created_by) \
         SELECT ts.id, 'legacy_token', sha256(convert_to(ts.invite_token, 'UTF8')), ts.host_user_id \
         FROM terminal_sessions ts \
         LEFT JOIN terminal_session_grants g \
           ON g.session_id = ts.id AND g.kind = 'legacy_token' \
         WHERE ts.invite_token IS NOT NULL AND ts.ended_at IS NULL AND g.id IS NULL \
         ON CONFLICT (secret_hash) DO NOTHING",
    )
    .execute(pool)
    .await;

    match result {
        Ok(res) => info!(
            reconciled = res.rows_affected(),
            "Reconciled legacy invite-token grants"
        ),
        Err(err) => {
            error!(error = %err, "Failed to reconcile legacy invite-token grants");
            panic!("Failed to reconcile legacy invite-token grants");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_session, seed_user};
    use uuid::Uuid;

    #[tokio::test]
    async fn reconciliation_backfills_a_grant_for_a_token_with_none() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let session = seed_session(&pool, host, "invite_link").await;
        let token = format!("fake-rollback-orphan-{}", Uuid::new_v4());

        sqlx::query("UPDATE terminal_sessions SET invite_token = $1 WHERE id = $2")
            .bind(&token)
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();

        reconcile_legacy_grants(&pool).await;

        assert!(
            crate::session_grants::resolve_join_grant(&pool, session, &token).await,
            "reconciliation must mint a resolvable grant"
        );
    }

    #[tokio::test]
    async fn reconciliation_is_idempotent() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let session = seed_session(&pool, host, "invite_link").await;
        let token = format!("fake-rollback-orphan-{}", Uuid::new_v4());

        sqlx::query("UPDATE terminal_sessions SET invite_token = $1 WHERE id = $2")
            .bind(&token)
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();

        reconcile_legacy_grants(&pool).await;
        reconcile_legacy_grants(&pool).await;

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_grants \
             WHERE session_id = $1 AND kind = 'legacy_token'",
        )
        .bind(session)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "second run must insert nothing new");
    }

    #[tokio::test]
    async fn migrator_boots_past_versions_this_build_lacks() {
        let pool = test_pool_or_skip!();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES (9000000000000000000, 'from a newer image', TRUE, '\\x00'::bytea, 0)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();

        let mut strict = sqlx::migrate!("./migrations");
        strict.set_locking(false);
        assert!(matches!(
            strict.run(&mut *tx).await,
            Err(sqlx::migrate::MigrateError::VersionMissing(9000000000000000000))
        ));
        let mut lenient = migrator();
        lenient.set_locking(false);
        lenient.run(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
}
