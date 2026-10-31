//! `DELETE /v1/auth/account`: a user deleting their own account.
//!
//! One transaction, in this order:
//! 1. Teams the user is the billing owner of (`teams.owner_id`). If another
//!    member holds the Owner role, the earliest-joined one becomes the billing
//!    owner and the user then leaves like any member. Otherwise a team with no
//!    other member goes with them, and a team that still has members refuses
//!    the whole deletion with `409 OWNS_TEAM_WITH_MEMBERS` (the user must make
//!    someone else an Owner, remove the members, or delete the team first).
//!    Teams where the user is an Owner but not the billing owner need nothing
//!    special: other Owners may leave.
//! 2. Teams the user is only a member of: the same cleanup as leaving
//!    (`teams::remove_member`) — their member rule entries go and a key rotation
//!    is queued, since they held the team key.
//! 3. Their public key is kept if a teammate's copy of a team key was wrapped by
//!    them (migration 061 explains why), then the user row is deleted. Every
//!    other reference cascades or goes NULL.
//! 4. A subscription that would still renew is cancelled at Lemon Squeezy
//!    *before* the commit. If that fails nothing is deleted
//!    (`502 SUBSCRIPTION_CANCEL_FAILED`): a deleted account must never keep
//!    being billed. The reverse failure (cancelled, then the commit fails) only
//!    leaves an existing account whose plan runs to the end of the period.

use std::future::Future;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::routes::teams::{delete_subject_rule_entries, notify_team_members_changed, request_team_rotation};
use crate::self_host;
use crate::team_plan::after_billing_owner_change;
use crate::sync_notifier::SyncNotifier;

const LS_CANCEL_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlockingTeam {
    pub id: Uuid,
    pub name: String,
    pub other_members: i64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum DeleteAccountError {
    NotFound,
    OwnsTeamWithMembers(Vec<BlockingTeam>),
    SubscriptionCancelFailed,
    Internal,
}

impl IntoResponse for DeleteAccountError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::NotFound => (StatusCode::NOT_FOUND, serde_json::json!({ "error": "NOT_FOUND" })),
            Self::OwnsTeamWithMembers(teams) => (
                StatusCode::CONFLICT,
                serde_json::json!({
                    "error": "OWNS_TEAM_WITH_MEMBERS",
                    "message": "You are the only Owner of a team that still has members. Make another member an Owner, remove the members, or delete the team first.",
                    "teams": teams,
                }),
            ),
            Self::SubscriptionCancelFailed => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({ "error": "SUBSCRIPTION_CANCEL_FAILED" }),
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "ACCOUNT_DELETE_FAILED" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct DeletedAccount {
    /// Teams the user left (as member, co-owner, or handing billing to another
    /// Owner); their rosters changed.
    pub left_teams: Vec<Uuid>,
    /// Teams the user owned alone, deleted with them.
    pub deleted_teams: Vec<Uuid>,
    /// (team, new billing owner) for teams another Owner took over.
    pub handed_over: Vec<(Uuid, Uuid)>,
    pub cancelled_subscription: Option<String>,
}

fn db_err(e: sqlx::Error, what: &'static str, user_id: Uuid) -> DeleteAccountError {
    error!(error = %e, user_id = %user_id, what, "Account deletion failed");
    DeleteAccountError::Internal
}

/// The deletion itself, with the Lemon Squeezy call injected so tests can drive
/// both outcomes without the network. `cancel` receives the subscription id and
/// is only called for a subscription that would still renew.
pub(crate) async fn delete_account_inner<F, Fut>(
    pool: &PgPool,
    user_id: Uuid,
    cancel: F,
) -> Result<DeletedAccount, DeleteAccountError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), StatusCode>>,
{
    let mut tx = pool.begin().await.map_err(|e| db_err(e, "begin", user_id))?;

    // Locks the row so a concurrent subscription webhook or second delete waits.
    let renewing_subscription: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT CASE WHEN ls_subscription_id IS NOT NULL
                       AND NOT subscription_cancelled
                       AND COALESCE(ls_subscription_status, '') NOT IN ('cancelled', 'expired')
                     THEN ls_subscription_id END
           FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| db_err(e, "lock user", user_id))?
    .ok_or(DeleteAccountError::NotFound)?;

    // FOR UPDATE on the team rows: a concurrent join takes a KEY SHARE lock on
    // the team it references, so it waits for this and then fails on the
    // deleted team instead of slipping in between the check and the delete.
    let owned: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT t.id, t.name,
                (SELECT COUNT(*) FROM team_members m WHERE m.team_id = t.id AND m.user_id <> $1)
           FROM teams t WHERE t.owner_id = $1
          ORDER BY t.created_at
            FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| db_err(e, "list owned teams", user_id))?;

    let mut blocking = Vec::new();
    let mut deleted_teams = Vec::new();
    let mut handed_over = Vec::new();
    for (team_id, name, others) in owned {
        // Another Owner takes billing over; the earliest to join, for determinism.
        let successor: Option<Uuid> = sqlx::query_scalar(
            "SELECT m.user_id FROM team_members m
               JOIN team_member_roles tmr ON tmr.team_id = m.team_id AND tmr.user_id = m.user_id
               JOIN team_roles tr ON tr.id = tmr.role_id AND tr.is_builtin AND tr.name = 'owner'
              WHERE m.team_id = $1 AND m.user_id <> $2
              ORDER BY m.joined_at, m.user_id
              LIMIT 1",
        )
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| db_err(e, "find successor owner", user_id))?;
        match successor {
            Some(next) => handed_over.push((team_id, next)),
            None if others > 0 => blocking.push(BlockingTeam { id: team_id, name, other_members: others }),
            None => deleted_teams.push(team_id),
        }
    }
    if !blocking.is_empty() {
        return Err(DeleteAccountError::OwnsTeamWithMembers(blocking));
    }

    for (team_id, next) in &handed_over {
        sqlx::query("UPDATE teams SET owner_id = $2 WHERE id = $1")
            .bind(team_id)
            .bind(next)
            .execute(&mut *tx)
            .await
            .map_err(|e| db_err(e, "hand over billing owner", user_id))?;
        info!(team_id = %team_id, from = %user_id, to = %next, "Billing owner handed over on account deletion");
    }

    sqlx::query("DELETE FROM teams WHERE id = ANY($1)")
        .bind(&deleted_teams)
        .execute(&mut *tx)
        .await
        .map_err(|e| db_err(e, "delete owned teams", user_id))?;

    let left_teams: Vec<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM team_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| db_err(e, "list memberships", user_id))?;
    for team_id in &left_teams {
        // Membership, roles, overrides and wrapped keys cascade from the user
        // row; rule entries naming them do not (subject_id carries no FK).
        delete_subject_rule_entries(&mut tx, *team_id, "member", user_id)
            .await
            .map_err(|_| DeleteAccountError::Internal)?;
        request_team_rotation(&mut tx, *team_id)
            .await
            .map_err(|_| DeleteAccountError::Internal)?;
    }

    crate::routes::users::retire_public_key_if_wrapper(&mut *tx, user_id)
        .await
        .map_err(|e| db_err(e, "retire public key", user_id))?;

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| db_err(e, "delete user", user_id))?;

    if let Some(subscription_id) = &renewing_subscription {
        if let Err(status) = cancel(subscription_id.clone()).await {
            error!(user_id = %user_id, subscription_id = %subscription_id, %status,
                "Could not cancel the subscription; account not deleted");
            return Err(DeleteAccountError::SubscriptionCancelFailed);
        }
    }

    if let Err(e) = tx.commit().await {
        if let Some(subscription_id) = &renewing_subscription {
            // The account still exists and its plan now ends with the period;
            // the user can resume it or retry the deletion.
            error!(error = %e, user_id = %user_id, subscription_id = %subscription_id,
                "Subscription cancelled but account deletion did not commit");
        }
        return Err(db_err(e, "commit", user_id));
    }

    Ok(DeletedAccount { left_teams, deleted_teams, handed_over, cancelled_subscription: renewing_subscription })
}

/// Lemon Squeezy cancellation for the live server: stop renewal. Self-hosted
/// servers have no billing, so nothing can renew there.
async fn cancel_renewal(subscription_id: String) -> Result<(), StatusCode> {
    if self_host::is_self_hosted() {
        warn!(subscription_id = %subscription_id, "Self-hosted: not calling Lemon Squeezy");
        return Ok(());
    }
    match tokio::time::timeout(
        LS_CANCEL_TIMEOUT,
        crate::routes::billing::cancel_ls_subscription(&subscription_id),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(StatusCode::GATEWAY_TIMEOUT),
    }
}

// `Response` in the Err slot carries the coded JSON body; see billing.rs.
#[allow(clippy::result_large_err)]
pub async fn delete_account(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
) -> Result<StatusCode, Response> {
    let deleted = match delete_account_inner(&pool, auth.0, cancel_renewal).await {
        Ok(d) => d,
        Err(DeleteAccountError::OwnsTeamWithMembers(teams)) => {
            info!(user_id = %auth.0, teams = teams.len(), "Account deletion refused: owns a team with members");
            return Err(DeleteAccountError::OwnsTeamWithMembers(teams).into_response());
        }
        Err(e) => return Err(e.into_response()),
    };

    info!(
        user_id = %auth.0,
        left_teams = deleted.left_teams.len(),
        deleted_teams = deleted.deleted_teams.len(),
        cancelled_subscription = deleted.cancelled_subscription.is_some(),
        "Account deleted"
    );

    announce_deletion(&pool, &notifier, auth.0, deleted).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn announce_deletion(pool: &PgPool, notifier: &SyncNotifier, user_id: Uuid, deleted: DeletedAccount) {
    notifier.notify(user_id, "token_invalidated".to_string());
    for team_id in deleted.left_teams {
        notify_team_members_changed(pool, notifier, team_id).await;
    }
    for (team_id, next) in deleted.handed_over {
        if let Err(status) = after_billing_owner_change(pool, notifier, team_id, user_id, next).await {
            error!(team_id = %team_id, %status, "Team plan reconcile failed after account deletion");
        }
    }
}

#[cfg(test)]
mod tests {
    //! DB-backed. Requires TEST_DATABASE_URL.
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    async fn no_ls(_: String) -> Result<(), StatusCode> {
        panic!("Lemon Squeezy must not be called");
    }

    async fn user_exists(pool: &PgPool, id: Uuid) -> bool {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn team_exists(pool: &PgPool, id: Uuid) -> bool {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn set_subscription(pool: &PgPool, user: Uuid, status: &str, cancelled: bool) -> String {
        let sub = format!("sub-{}", Uuid::new_v4());
        sqlx::query(
            "UPDATE users SET ls_subscription_id = $2, ls_subscription_status = $3,
                    subscription_cancelled = $4 WHERE id = $1",
        )
        .bind(user)
        .bind(&sub)
        .bind(status)
        .bind(cancelled)
        .execute(pool)
        .await
        .unwrap();
        sub
    }

    #[tokio::test]
    async fn a_user_without_teams_or_billing_is_deleted() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;

        let out = delete_account_inner(&pool, me, no_ls).await.unwrap();

        assert_eq!(out, DeletedAccount::default());
        assert!(!user_exists(&pool, me).await);
    }

    #[tokio::test]
    async fn an_unknown_user_is_not_found() {
        let pool = test_pool_or_skip!();
        let err = delete_account_inner(&pool, Uuid::new_v4(), no_ls).await.unwrap_err();
        assert_eq!(err, DeleteAccountError::NotFound);
    }

    #[tokio::test]
    async fn a_team_owned_alone_is_deleted_with_its_owner() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, me).await;
        seed_team_object(&pool, team, me, "obj-1", "connection").await;
        seed_session(&pool, me, "vault").await;

        let out = delete_account_inner(&pool, me, no_ls).await.unwrap();

        assert_eq!(out.deleted_teams, vec![team]);
        assert!(!team_exists(&pool, team).await);
        assert!(!user_exists(&pool, me).await);
    }

    #[tokio::test]
    async fn owning_a_team_with_members_refuses_and_changes_nothing() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        let sub = set_subscription(&pool, me, "active", false).await;
        let lonely = seed_team_with_roles(&pool, me).await;
        let shared = seed_team_with_roles(&pool, me).await;
        let mate = seed_user(&pool).await;
        add_member(&pool, shared, mate).await;

        let err = delete_account_inner(&pool, me, no_ls).await.unwrap_err();

        assert_eq!(
            err,
            DeleteAccountError::OwnsTeamWithMembers(vec![BlockingTeam {
                id: shared,
                name: "test-team".into(),
                other_members: 1,
            }])
        );
        assert!(user_exists(&pool, me).await);
        assert!(team_exists(&pool, lonely).await, "rolled back, not half-deleted");
        assert!(team_exists(&pool, shared).await);
        let still: Option<String> =
            sqlx::query_scalar("SELECT ls_subscription_id FROM users WHERE id = $1")
                .bind(me)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(still, Some(sub));
    }

    /// Everything a non-owner member leaves behind in someone else's team: the
    /// team keeps its history and objects, and their teammates keep their keys.
    #[tokio::test]
    async fn a_member_leaves_team_history_intact() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let me = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        add_member(&pool, team, me).await;
        add_member(&pool, team, mate).await;
        sqlx::query("UPDATE users SET public_key = 'pk-me' WHERE id = $1")
            .bind(me)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE team_members SET invited_by = $2 WHERE team_id = $1 AND user_id = $3")
            .bind(team)
            .bind(me)
            .bind(mate)
            .execute(&pool)
            .await
            .unwrap();

        crate::routes::audit::write_audit_event(pool.clone(), team, me, "vault.deleted", None, None, None, None).await;
        seed_team_object(&pool, team, me, "obj-by-me", "connection").await;
        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by)
             VALUES ($1, 's-by-me', 'obj-by-me', 'connection_password', 'ct', $2)",
        )
        .bind(team)
        .bind(me)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO team_sync_blobs (team_id, blob, size_bytes, updated_by) VALUES ($1, '\\x00', 1, $2)")
            .bind(team)
            .bind(me)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 2, $2)")
            .bind(team)
            .bind(me)
            .execute(&pool)
            .await
            .unwrap();
        let set = seed_rule_set(&pool, team, me, &[("member", Some(me), crate::permissions::PERM_VIEW, 0)]).await;
        sqlx::query(
            "INSERT INTO team_member_permission_overrides (team_id, user_id, allow_mask, deny_mask, updated_by)
             VALUES ($1, $2, 0, 0, $3)",
        )
        .bind(team)
        .bind(mate)
        .bind(me)
        .execute(&pool)
        .await
        .unwrap();
        // `me` wrapped the epoch-2 key for `mate`, and holds their own copy.
        seed_vault_key(&pool, team, mate, me, 2, true).await;
        seed_vault_key(&pool, team, me, owner, 2, true).await;
        seed_session(&pool, me, "vault").await;
        let rotations_before = rotation_request_count(&pool, team).await;

        let out = delete_account_inner(&pool, me, no_ls).await.unwrap();

        assert_eq!(out.left_teams, vec![team]);
        assert!(!user_exists(&pool, me).await);
        assert!(team_exists(&pool, team).await);

        let actor: Option<Uuid> = sqlx::query_scalar(
            "SELECT actor_id FROM audit_logs WHERE team_id = $1 AND action = 'vault.deleted'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(actor, None, "audit row survives, actor anonymised");
        let listed: Vec<(Option<Uuid>, String)> = sqlx::query_as(&format!(
            "SELECT al.actor_id, COALESCE(u.handle, '[deleted user]') FROM audit_logs al {} WHERE al.team_id = $1",
            crate::routes::audit::AUDIT_ACTOR_JOINS
        ))
        .bind(team)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(listed.contains(&(None, "[deleted user]".to_string())), "still listed: {listed:?}");

        for (table, col) in [
            ("team_vault_objects", "updated_by"),
            ("team_vault_secrets", "updated_by"),
            ("team_sync_blobs", "updated_by"),
            ("team_key_epochs", "created_by"),
            ("team_rule_sets", "updated_by"),
            ("team_member_permission_overrides", "updated_by"),
            ("team_members", "invited_by"),
        ] {
            let nulls: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE team_id = $1 AND {col} IS NULL"
            ))
            .bind(team)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(nulls >= 1, "{table}.{col} kept with NULL author");
        }

        let entries: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM team_rule_set_entries WHERE rule_set_id = $1")
                .bind(set)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(entries, 0, "rule entries naming the departed member are gone");
        assert!(rotation_request_count(&pool, team).await > rotations_before);

        // mate's wrap survives and its wrapper still resolves to a public key.
        let wrapper: Uuid = sqlx::query_scalar(
            "SELECT wrapped_by FROM team_vault_keys WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team)
        .bind(mate)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(wrapper, me);
        let key = crate::routes::users::public_key_for_unwrap(&pool, me).await.unwrap();
        assert_eq!(key.public_key, "pk-me");
    }

    #[tokio::test]
    async fn a_renewing_subscription_is_cancelled() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        let sub = set_subscription(&pool, me, "active", false).await;
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen2 = seen.clone();

        let out = delete_account_inner(&pool, me, move |id| async move {
            *seen2.lock().unwrap() = Some(id);
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(seen.lock().unwrap().clone(), Some(sub.clone()));
        assert_eq!(out.cancelled_subscription, Some(sub));
        assert!(!user_exists(&pool, me).await);
    }

    #[tokio::test]
    async fn a_failed_cancellation_keeps_the_account() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        set_subscription(&pool, me, "on_trial", false).await;
        let team = seed_team_with_roles(&pool, me).await;

        let err = delete_account_inner(&pool, me, |_| async { Err(StatusCode::BAD_GATEWAY) })
            .await
            .unwrap_err();

        assert_eq!(err, DeleteAccountError::SubscriptionCancelFailed);
        assert!(user_exists(&pool, me).await);
        assert!(team_exists(&pool, team).await);
    }

    #[tokio::test]
    async fn a_subscription_that_no_longer_renews_is_left_alone() {
        let pool = test_pool_or_skip!();
        for (status, cancelled) in [("active", true), ("cancelled", true), ("expired", false)] {
            let me = seed_user(&pool).await;
            set_subscription(&pool, me, status, cancelled).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let c = calls.clone();
            delete_account_inner(&pool, me, move |_| async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 0, "{status}/{cancelled}");
            assert!(!user_exists(&pool, me).await);
        }
    }

    async fn billing_owner(pool: &PgPool, team: Uuid) -> Uuid {
        sqlx::query_scalar("SELECT owner_id FROM teams WHERE id = $1").bind(team).fetch_one(pool).await.unwrap()
    }

    #[tokio::test]
    async fn a_billing_owner_with_a_co_owner_hands_over_and_leaves() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, me).await;
        let plain = seed_user(&pool).await;
        add_member(&pool, team, plain).await;
        let co = seed_user(&pool).await;
        add_member(&pool, team, co).await;
        grant_builtin_role(&pool, team, co, "owner").await;

        let out = delete_account_inner(&pool, me, no_ls).await.unwrap();

        assert_eq!(out.handed_over, vec![(team, co)]);
        assert_eq!(out.left_teams, vec![team]);
        assert!(out.deleted_teams.is_empty());
        assert!(!user_exists(&pool, me).await);
        assert!(team_exists(&pool, team).await);
        assert_eq!(billing_owner(&pool, team).await, co, "never handed to a non-Owner");
    }

    #[tokio::test]
    async fn a_handover_tells_the_new_billing_owner_and_members_their_plan_changed() {
        let _mode = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        set_user_tier(&pool, me, "teams").await;
        let team = seed_team_with_roles(&pool, me).await;
        let plain = seed_user(&pool).await;
        add_member(&pool, team, plain).await;
        let co = seed_user(&pool).await;
        add_member(&pool, team, co).await;
        grant_builtin_role(&pool, team, co, "owner").await;
        let notifier = SyncNotifier::new();
        crate::team_plan::reconcile_team_plan(&pool, &notifier, team).await.unwrap();

        let out = delete_account_inner(&pool, me, no_ls).await.unwrap();
        let mut rx = notifier.subscribe();
        announce_deletion(&pool, &notifier, me, out).await;

        let mut got = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::sync_notifier::SyncEvent::PlanChanged { user_id } = ev {
                got.push(user_id);
            }
        }
        assert!(got.contains(&co));
        assert!(got.contains(&plain));
    }

    #[tokio::test]
    async fn a_co_owner_who_is_not_billing_owner_just_leaves() {
        let pool = test_pool_or_skip!();
        let boss = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, boss).await;
        let me = seed_user(&pool).await;
        add_member(&pool, team, me).await;
        grant_builtin_role(&pool, team, me, "owner").await;

        let out = delete_account_inner(&pool, me, no_ls).await.unwrap();

        assert_eq!(out.left_teams, vec![team]);
        assert!(out.handed_over.is_empty());
        assert_eq!(billing_owner(&pool, team).await, boss);
        assert!(!user_exists(&pool, me).await);
    }

    #[tokio::test]
    async fn a_sole_owner_with_non_owner_members_is_refused() {
        let pool = test_pool_or_skip!();
        let me = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, me).await;
        let admin = member_with_role(&pool, team, crate::permissions::PERM_ADMINISTRATOR).await;

        let err = delete_account_inner(&pool, me, no_ls).await.unwrap_err();

        assert!(matches!(err, DeleteAccountError::OwnsTeamWithMembers(ref t) if t.len() == 1 && t[0].id == team));
        assert_eq!(billing_owner(&pool, team).await, me);
        assert!(user_exists(&pool, admin).await);
    }

    #[tokio::test]
    async fn the_409_names_the_code_the_app_maps() {
        let res = DeleteAccountError::OwnsTeamWithMembers(vec![]).into_response();
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "OWNS_TEAM_WITH_MEMBERS");

        let res = DeleteAccountError::SubscriptionCancelFailed.into_response();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "SUBSCRIPTION_CANCEL_FAILED");
    }
}
