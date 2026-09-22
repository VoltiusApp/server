use sqlx::{Connection, PgConnection};
use tracing::{error, info, warn};

/// Arbitrary but fixed: "voltius" in ASCII, truncated. Any second process using
/// this database must pick the same number or the guard is pointless.
const LOCK_KEY: i64 = 0x0076_6F6C_7469_7573;

/// Held for the process lifetime. Dropping it releases the lock, which is what
/// makes a crashed or stopped instance free it without any cleanup step.
pub struct InstanceLock {
    _conn: PgConnection,
}

/// Refuses to start when another process already holds the lock on this
/// database. Several instances cannot serve correctly yet — the sync notifier,
/// terminal sessions, rate limiters and presence are all per-process, so a
/// second one disagrees with the first silently. Set
/// `ALLOW_MULTIPLE_INSTANCES=true` once that is no longer true.
pub async fn acquire(database_url: &str) -> Option<InstanceLock> {
    if std::env::var("ALLOW_MULTIPLE_INSTANCES")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        warn!("ALLOW_MULTIPLE_INSTANCES=true: not checking for another instance");
        return None;
    }

    // A session lock lives on one connection, so this one is kept out of the
    // pool: a pooled connection would be recycled and drop the lock.
    let mut conn = PgConnection::connect(database_url).await.unwrap_or_else(|e| {
        error!(error = %e, "Instance guard could not reach the database");
        std::process::exit(1);
    });

    let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(LOCK_KEY)
        .fetch_one(&mut conn)
        .await
        .unwrap_or_else(|e| {
            error!(error = %e, "Instance guard could not take the lock");
            std::process::exit(1);
        });

    if !taken {
        error!(
            "another voltius-server is already running against this database. \
             Several instances cannot serve correctly yet: sync events, terminal \
             sessions, rate limits and presence are per-process, and a second \
             instance disagrees with the first without erroring. Stop the other \
             one, or set ALLOW_MULTIPLE_INSTANCES=true if you know it is safe."
        );
        std::process::exit(1);
    }

    info!("Instance lock held; no other server is using this database");
    Some(InstanceLock { _conn: conn })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_instance_cannot_take_the_lock() {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };

        let mut first = PgConnection::connect(&url).await.expect("connect");
        let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(LOCK_KEY)
            .fetch_one(&mut first)
            .await
            .expect("first lock");
        assert!(taken, "nothing else should hold the lock in a test database");

        let mut second = PgConnection::connect(&url).await.expect("connect");
        let taken_again: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(LOCK_KEY)
            .fetch_one(&mut second)
            .await
            .expect("second lock");
        assert!(!taken_again, "a second instance must not get the lock");

        drop(first);
        // Postgres releases on disconnect, which can lag the client's drop.
        for _ in 0..50 {
            let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(LOCK_KEY)
                .fetch_one(&mut second)
                .await
                .expect("retry lock");
            if free {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("the lock was never released after the holder disconnected");
    }
}
