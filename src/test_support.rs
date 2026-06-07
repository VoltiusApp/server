//! Shared helpers for DB-backed integration tests (compiled only under `cfg(test)`).
//!
//! Tests connect to the Postgres pointed at by `TEST_DATABASE_URL` and run the
//! real migrations. When the variable is unset, `test_pool()` returns `None` so
//! callers skip — keeping `cargo test` green without a database (e.g. for
//! contributors who only touch pure-function code).
//!
//! Point it at the compose Postgres, e.g.:
//!   TEST_DATABASE_URL=postgres://voltius:voltius@localhost:5432/voltius_test cargo test

use sqlx::PgPool;
use uuid::Uuid;

/// Connect to `TEST_DATABASE_URL` and apply migrations, or return `None` to skip.
pub async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("TEST_DATABASE_URL").ok()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    // sqlx's migrator takes a Postgres advisory lock, so concurrent test
    // invocations applying migrations is safe.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations on test database");
    Some(pool)
}

/// Skip the enclosing test (returning early) unless a test database is configured.
#[macro_export]
macro_rules! test_pool_or_skip {
    () => {
        match $crate::test_support::test_pool().await {
            Some(pool) => pool,
            None => {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            }
        }
    };
}

/// Insert a minimal valid user and return its id. Each call uses fresh UUIDs so
/// tests never collide on the unique `email`/`account_id` columns.
pub async fn seed_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, account_id, auth_hash, public_key, display_name)
         VALUES ($1, $2, $3, 'test-hash', 'test-pubkey', 'Test User')",
    )
    .bind(id)
    .bind(format!("{id}@test.local"))
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Insert a team owned by `owner` and return its id.
pub async fn seed_team(pool: &PgPool, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO teams (id, name, owner_id) VALUES ($1, 'test-team', $2)")
        .bind(id)
        .bind(owner)
        .execute(pool)
        .await
        .expect("seed team");
    id
}

/// Insert a role with the given permission bits and return its id.
pub async fn seed_role(pool: &PgPool, team: Uuid, name: &str, permissions: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO team_roles (id, team_id, name, permissions, is_builtin)
         VALUES ($1, $2, $3, $4, FALSE)",
    )
    .bind(id)
    .bind(team)
    .bind(name)
    .bind(permissions)
    .execute(pool)
    .await
    .expect("seed role");
    id
}

/// Add `user` to `team` as a member.
pub async fn add_member(pool: &PgPool, team: Uuid, user: Uuid) {
    sqlx::query("INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)")
        .bind(team)
        .bind(user)
        .execute(pool)
        .await
        .expect("add member");
}

/// Assign `role` to `user` within `team`.
pub async fn assign_role(pool: &PgPool, team: Uuid, user: Uuid, role: Uuid) {
    sqlx::query("INSERT INTO team_member_roles (team_id, user_id, role_id) VALUES ($1, $2, $3)")
        .bind(team)
        .bind(user)
        .bind(role)
        .execute(pool)
        .await
        .expect("assign role");
}
