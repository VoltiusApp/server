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
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// Serializes tests that mutate process-global env vars (e.g. `LS_VARIANT_*`).
/// Without this, parallel tests race on shared env and fail intermittently.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the global env lock for the duration of a test. Tolerates poisoning
/// (a prior test panicking while holding it) so one failure doesn't cascade.
pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serializes tests that read or write `users.last_seen_on`. Activity counts are
/// whole-table aggregates, so a concurrent test stamping a user would shift the
/// totals mid-assertion. Any test touching that column must hold this lock.
///
/// Async-aware, unlike [`ENV_LOCK`]: these tests hold the guard across `.await`
/// (they query the database while holding it), which a `std` guard forbids.
static LAST_SEEN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Acquire the `last_seen_on` lock for the duration of a test.
pub async fn last_seen_lock() -> tokio::sync::MutexGuard<'static, ()> {
    LAST_SEEN_LOCK.lock().await
}

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

/// Default-budget knock limiter for tests that don't care about the knock
/// limit itself — only tests exercising the limit construct their own.
pub fn default_knock_limiter() -> crate::rate_limit::KnockRateLimiter {
    crate::rate_limit::KnockRateLimiter(crate::rate_limit::RateLimiter::new(
        20,
        std::time::Duration::from_secs(3600),
    ))
}

/// Insert a minimal valid user and return its id. Each call uses fresh UUIDs so
/// tests never collide on the unique `email`/`account_id` columns.
pub async fn seed_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let handle = crate::handles::generate_unique_handle(pool)
        .await
        .expect("generate handle");
    sqlx::query(
        "INSERT INTO users (id, email, account_id, auth_hash, public_key, display_name, handle)
         VALUES ($1, $2, $3, 'test-hash', 'test-pubkey', 'Test User', $4)",
    )
    .bind(id)
    .bind(format!("{id}@test.local"))
    .bind(Uuid::new_v4())
    .bind(&handle)
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Seed a user with a real Argon2 `auth_hash` for `auth_key` and the given
/// `account_id`, so `login` handler tests can present verifiable credentials
/// (the default `seed_user` stores a non-verifiable placeholder hash).
pub async fn seed_user_with_credentials(pool: &PgPool, account_id: Uuid, auth_key: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = crate::auth::password::hash_auth_key(auth_key).expect("hash auth key");
    let handle = crate::handles::generate_unique_handle(pool)
        .await
        .expect("generate handle");
    sqlx::query(
        "INSERT INTO users (id, email, account_id, auth_hash, public_key, display_name, handle)
         VALUES ($1, $2, $3, $4, 'test-pubkey', 'Test User', $5)",
    )
    .bind(id)
    .bind(format!("{id}@test.local"))
    .bind(account_id)
    .bind(&hash)
    .bind(&handle)
    .execute(pool)
    .await
    .expect("seed user with credentials");
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

/// Seed a user, grant them a single role with exactly `perms`, add them to
/// `team`, and assign the role. Returns the new member's id. The common setup
/// for handler authorization tests.
///
/// The role name is suffixed with a fresh UUID: `team_roles` has a unique
/// `(team_id, name)` constraint, and callers routinely seed more than one
/// member (e.g. caller + victim) on the same team.
pub async fn member_with_role(pool: &PgPool, team: Uuid, perms: i64) -> Uuid {
    let user = seed_user(pool).await;
    let role_name = format!("authz-test-role-{}", Uuid::new_v4());
    let role = seed_role(pool, team, &role_name, perms).await;
    add_member(pool, team, user).await;
    assign_role(pool, team, user, role).await;
    user
}

/// Set a user's `subscription_tier` (e.g. "business"). Used by tier-gated
/// handler tests; the seed default is 'free'.
pub async fn set_user_tier(pool: &PgPool, user: Uuid, tier: &str) {
    sqlx::query("UPDATE users SET subscription_tier = $1 WHERE id = $2")
        .bind(tier)
        .bind(user)
        .execute(pool)
        .await
        .expect("set user tier");
}

/// Set a user's seat cap (`users.seat_count`). NULL means unlimited; this sets a
/// concrete cap for seat-limit tests.
pub async fn set_user_seats(pool: &PgPool, user: Uuid, seats: i32) {
    sqlx::query("UPDATE users SET seat_count = $1 WHERE id = $2")
        .bind(seats)
        .bind(user)
        .execute(pool)
        .await
        .expect("set user seats");
}

/// Put a user on an active trial ending `days` from now. Seat-limit tests use this
/// to exercise the trial branch that clamps the effective seat cap to 10. Note the
/// clamp keys on `trial_ends_at IS NOT NULL`, so any non-null value triggers it
/// regardless of `days` — the magnitude only matters if a caller later checks it.
pub async fn set_user_trial(pool: &PgPool, user: Uuid, days: i64) {
    sqlx::query("UPDATE users SET trial_ends_at = now() + ($1 * interval '1 day') WHERE id = $2")
        .bind(days)
        .bind(user)
        .execute(pool)
        .await
        .expect("set user trial");
}

/// The deterministic email `seed_user` assigns, so invitation tests can target a
/// seeded user by the exact address their acceptance handler will compare against.
pub fn test_user_email(id: Uuid) -> String {
    format!("{id}@test.local")
}

/// Insert a pending invitation and return `(invitation_id, token)`. `user_id` is the
/// in-app recipient binding (NULL for link-only invites). The token is a fresh UUID
/// hex string so tests can look the invitation up by token.
pub async fn seed_invitation(
    pool: &PgPool,
    team: Uuid,
    email: &str,
    role: &str,
    user_id: Option<Uuid>,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let token = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "INSERT INTO pending_invitations (id, team_id, email, role, token, user_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(team)
    .bind(email)
    .bind(role)
    .bind(&token)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed invitation");
    (id, token)
}

/// Insert a team-vault object row directly (bypassing the write handler) so
/// presence/prefs tests have a real object to reference. `object_type` must be
/// one of the CHECK-constrained values (e.g. "connection"). `updated_by` is set
/// to the team owner for FK validity.
pub async fn seed_team_object(
    pool: &PgPool,
    team: Uuid,
    owner: Uuid,
    object_id: &str,
    object_type: &str,
) {
    sqlx::query(
        "INSERT INTO team_vault_objects
           (team_id, object_id, object_type, vault_id, updated_by)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(team)
    .bind(object_id)
    .bind(object_type)
    .bind(Uuid::new_v4())
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed team object");
}
