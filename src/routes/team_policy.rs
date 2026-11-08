use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::require_team_member;
use crate::routes::audit::write_audit_event;
use crate::routes::coded_error;
use crate::routes::teams::{notify_team_members_changed, require_vault_manager};
use crate::sync_notifier::SyncNotifier;
use crate::team_plan::require_granular;
use crate::team_policy::{is_narrowing, key_diff, lock_policy_of, validate_doc, DocError};

#[derive(Serialize, sqlx::FromRow)]
pub struct TeamPolicy {
    policy: Option<Value>,
    revision: i64,
    updated_at: Option<DateTime<Utc>>,
    updated_by: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct PutPolicy {
    pub policy: Value,
    pub revision: i64,
}

fn db_error(e: sqlx::Error) -> StatusCode {
    error!(error = %e, "Team policy query failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn doc_error(e: DocError) -> Response {
    let mut body = json!({ "error": e.code() });
    if let Some(key) = e.key() {
        body["key"] = json!(key);
    }
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

pub(crate) struct LockedPolicy {
    tx: Transaction<'static, Postgres>,
    team_id: Uuid,
    pub doc: Option<Value>,
    pub revision: i64,
}

impl LockedPolicy {
    pub(crate) async fn lock(pool: &PgPool, team_id: Uuid) -> Result<Self, StatusCode> {
        let mut tx = pool.begin().await.map_err(db_error)?;
        let (doc, revision) =
            sqlx::query_as("SELECT policy, policy_revision FROM teams WHERE id = $1 FOR UPDATE")
                .bind(team_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?
                .ok_or(StatusCode::NOT_FOUND)?;
        Ok(Self {
            tx,
            team_id,
            doc,
            revision,
        })
    }

    /// Also mirrors the app-lock keys into the `lock_*` columns so a server rollback keeps them.
    pub(crate) async fn replace(
        mut self,
        actor: Uuid,
        doc: Option<&Value>,
    ) -> Result<i64, StatusCode> {
        let lock = lock_policy_of(doc);
        let revision = sqlx::query_scalar(
            "UPDATE teams SET policy = $2, policy_revision = policy_revision + 1,
                    policy_updated_at = now(), policy_updated_by = $3,
                    lock_max_minutes = $4, lock_force_vault = $5
             WHERE id = $1 RETURNING policy_revision",
        )
        .bind(self.team_id)
        .bind(doc)
        .bind(actor)
        .bind(lock.map(|p| p.max_minutes))
        .bind(lock.is_some_and(|p| p.force_vault))
        .fetch_one(&mut *self.tx)
        .await
        .map_err(db_error)?;
        self.tx.commit().await.map_err(db_error)?;
        Ok(revision)
    }
}

pub(crate) async fn announce(
    pool: &PgPool,
    notifier: &SyncNotifier,
    team_id: Uuid,
    actor: Uuid,
    action: &str,
    metadata: Option<Value>,
) {
    write_audit_event(
        pool.clone(),
        team_id,
        actor,
        action,
        Some("team"),
        Some(team_id.to_string()),
        None,
        metadata,
    )
    .await;
    notify_team_members_changed(pool, notifier, team_id).await;
}

pub async fn get_policy(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<TeamPolicy>, StatusCode> {
    require_team_member(&pool, team_id, auth.0).await?;
    sqlx::query_as(
        "SELECT policy, policy_revision AS revision, policy_updated_at AS updated_at,
                policy_updated_by AS updated_by
         FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .fetch_one(&pool)
    .await
    .map(Json)
    .map_err(db_error)
}

pub async fn put_policy(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PutPolicy>,
) -> axum::response::Result<StatusCode> {
    require_vault_manager(&pool, team_id, auth.0).await?;
    validate_doc(&body.policy).map_err(doc_error)?;
    let locked = LockedPolicy::lock(&pool, team_id).await?;
    if locked.revision != body.revision {
        return Err(coded_error(StatusCode::CONFLICT, "POLICY_REVISION_MISMATCH").into());
    }
    require_granular(
        &pool,
        team_id,
        is_narrowing(locked.doc.as_ref(), &body.policy),
    )
    .await?;
    let diff = key_diff(locked.doc.as_ref(), Some(&body.policy));
    let revision = locked.replace(auth.0, Some(&body.policy)).await?;
    let metadata = json!({ "diff": diff, "revision": revision });
    announce(
        &pool,
        &notifier,
        team_id,
        auth.0,
        "team.policy_set",
        Some(metadata),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_policy(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    require_vault_manager(&pool, team_id, auth.0).await?;
    LockedPolicy::lock(&pool, team_id)
        .await?
        .replace(auth.0, None)
        .await?;
    announce(
        &pool,
        &notifier,
        team_id,
        auth.0,
        "team.policy_removed",
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{PERM_MANAGE_MEMBERS, PERM_MANAGE_VAULT};
    use crate::routes::team_lock_policy::tests::{clear as clear_lock, put as put_lock};
    use crate::team_policy::LockPolicy;
    use crate::test_support::{
        listed_team as listed, member_with_role, seed_team_with_roles, seed_user, set_user_tier,
        team_audit_count as audit_count, team_members_told, BillingMode,
    };

    fn doc(policy: Value) -> Value {
        json!({"version": 1, "policy": policy})
    }

    async fn put(
        pool: &PgPool,
        notifier: &SyncNotifier,
        team: Uuid,
        user: Uuid,
        policy: Value,
        revision: i64,
    ) -> (StatusCode, Value) {
        let resp = put_policy(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier.clone()),
            Path(team),
            Json(PutPolicy { policy, revision }),
        )
        .await
        .into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn put_status(
        pool: &PgPool,
        team: Uuid,
        user: Uuid,
        policy: Value,
        revision: i64,
    ) -> StatusCode {
        put(pool, &SyncNotifier::new(), team, user, policy, revision)
            .await
            .0
    }

    async fn delete(
        pool: &PgPool,
        notifier: &SyncNotifier,
        team: Uuid,
        user: Uuid,
    ) -> Result<StatusCode, StatusCode> {
        delete_policy(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier.clone()),
            Path(team),
        )
        .await
    }

    async fn get(pool: &PgPool, team: Uuid, user: Uuid) -> Result<Value, StatusCode> {
        get_policy(State(pool.clone()), Extension(AuthUser(user)), Path(team))
            .await
            .map(|Json(r)| serde_json::to_value(r).unwrap())
    }

    async fn lock_columns(pool: &PgPool, team: Uuid) -> (Option<i32>, bool) {
        sqlx::query_as("SELECT lock_max_minutes, lock_force_vault FROM teams WHERE id = $1")
            .bind(team)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn self_hosted_team() -> Option<(BillingMode, PgPool, Uuid, Uuid)> {
        let env = BillingMode::self_hosted();
        let pool = crate::test_support::test_pool().await?;
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        Some((env, pool, owner, team))
    }

    #[tokio::test]
    async fn put_then_list_teams_returns_doc_revision_and_joined_at() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let policy = doc(json!({"sync.types.key": false}));

        assert_eq!(
            put_status(&pool, team, owner, policy.clone(), 0).await,
            StatusCode::NO_CONTENT
        );

        let joined_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT joined_at FROM team_members WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team)
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        let t = listed(&pool, team, owner).await;
        assert_eq!(t.policy, Some(policy.clone()));
        assert_eq!(t.policy_revision, 1);
        assert_eq!(t.joined_at, joined_at);
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["policy"], policy);
        assert_eq!(json["policy_revision"], 1);
        assert!(json["joined_at"].is_string());

        let got = get(&pool, team, owner).await.unwrap();
        assert_eq!(got["policy"], policy);
        assert_eq!(got["revision"], 1);
        assert_eq!(got["updated_by"], json!(owner));
        assert!(got["updated_at"].is_string());
    }

    #[tokio::test]
    async fn put_with_stale_revision_is_409_and_keeps_stored() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let first = doc(json!({"a.b": 1}));
        assert_eq!(
            put_status(&pool, team, owner, first.clone(), 0).await,
            StatusCode::NO_CONTENT
        );

        let (status, body) = put(
            &pool,
            &SyncNotifier::new(),
            team,
            owner,
            doc(json!({"a.b": 2})),
            0,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "POLICY_REVISION_MISMATCH"}));

        let got = get(&pool, team, owner).await.unwrap();
        assert_eq!(got["policy"], first);
        assert_eq!(got["revision"], 1);
    }

    #[tokio::test]
    async fn put_rejects_machine_only_key_with_key_in_body() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let (status, body) = put(
            &pool,
            &SyncNotifier::new(),
            team,
            owner,
            doc(json!({"server.url": "https://example.com"})),
            0,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            json!({"error": "POLICY_MACHINE_ONLY_KEY", "key": "server.url"})
        );

        let (status, body) = put(
            &pool,
            &SyncNotifier::new(),
            team,
            owner,
            json!({"version": 2}),
            0,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "POLICY_INVALID"}));
        assert_eq!(
            get(&pool, team, owner).await.unwrap()["policy"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn member_without_manage_vault_gets_403_on_put_and_200_on_get() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let member = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let manager = member_with_role(&pool, team, PERM_MANAGE_VAULT).await;
        let outsider = seed_user(&pool).await;
        let policy = doc(json!({"a.b": 1}));

        assert_eq!(
            put_status(&pool, team, member, policy.clone(), 0).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            delete(&pool, &SyncNotifier::new(), team, member).await,
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            put_status(&pool, team, manager, policy.clone(), 0).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(get(&pool, team, member).await.unwrap()["policy"], policy);
        assert_eq!(get(&pool, team, outsider).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(
            get(&pool, team, owner).await.unwrap()["updated_by"],
            json!(manager)
        );
    }

    #[tokio::test]
    async fn below_business_put_402_but_removal_put_and_delete_allowed() {
        let _env = BillingMode::hosted();
        let Some(pool) = crate::test_support::test_pool().await else {
            return;
        };
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "business").await;
        let team = seed_team_with_roles(&pool, owner).await;
        assert_eq!(
            put_status(&pool, team, owner, doc(json!({"a.b": 1, "c.d": 2})), 0).await,
            StatusCode::NO_CONTENT
        );
        set_user_tier(&pool, owner, "teams").await;

        assert_eq!(
            put_status(
                &pool,
                team,
                owner,
                doc(json!({"a.b": 1, "c.d": 2, "e.f": 3})),
                1
            )
            .await,
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(
            put_status(&pool, team, owner, doc(json!({"a.b": 1})), 1).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            put_status(&pool, team, owner, doc(json!({"a.b": 9})), 2).await,
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(
            get(&pool, team, owner).await.unwrap()["policy"],
            doc(json!({"a.b": 1}))
        );
        assert_eq!(
            delete(&pool, &SyncNotifier::new(), team, owner).await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            get(&pool, team, owner).await.unwrap()["policy"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn put_and_delete_write_audit_and_notify_every_member() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let member = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        let (status, _) = put(&pool, &notifier, team, owner, doc(json!({"a.b": 1})), 0).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(audit_count(&pool, team, "team.policy_set").await, 1);
        let metadata: Value = sqlx::query_scalar(
            "SELECT metadata FROM audit_logs WHERE team_id = $1 AND action = 'team.policy_set'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            metadata,
            json!({"diff": {"added": ["a.b"], "changed": [], "removed": []}, "revision": 1})
        );
        let told = team_members_told(&mut rx, team);
        assert!(told.contains(&owner) && told.contains(&member));

        assert_eq!(
            delete(&pool, &notifier, team, owner).await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(audit_count(&pool, team, "team.policy_removed").await, 1);
        let told = team_members_told(&mut rx, team);
        assert!(told.contains(&owner) && told.contains(&member));
        assert_eq!(
            delete(&pool, &notifier, team, owner).await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[tokio::test]
    async fn lock_policy_put_writes_doc_and_keeps_other_keys() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        assert_eq!(
            put_status(&pool, team, owner, doc(json!({"sync.types.key": false})), 0).await,
            StatusCode::NO_CONTENT
        );

        assert_eq!(
            put_lock(&pool, team, owner, 15, true).await,
            Ok(StatusCode::NO_CONTENT)
        );

        let t = listed(&pool, team, owner).await;
        assert_eq!(
            t.policy,
            Some(doc(json!({
                "sync.types.key": false,
                "security.lockTimeoutMinutes": {"$range": {"max": 15}},
                "security.lockAction": "vault"
            })))
        );
        assert_eq!(t.policy_revision, 2);
        assert_eq!(
            t.lock_policy,
            Some(LockPolicy {
                max_minutes: 15,
                force_vault: true
            })
        );
        assert_eq!(lock_columns(&pool, team).await, (Some(15), true));
    }

    #[tokio::test]
    async fn lock_policy_delete_removes_only_app_lock_keys() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let other = doc(json!({"sync.types.key": false}));
        assert_eq!(
            put_status(&pool, team, owner, other.clone(), 0).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            put_lock(&pool, team, owner, 30, true).await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            clear_lock(&pool, team, owner).await,
            Ok(StatusCode::NO_CONTENT)
        );

        let t = listed(&pool, team, owner).await;
        assert_eq!(t.policy, Some(other));
        assert_eq!(t.policy_revision, 3);
        assert_eq!(t.lock_policy, None);
        assert_eq!(lock_columns(&pool, team).await, (None, false));
    }

    #[tokio::test]
    async fn teams_list_derives_lock_policy_from_doc() {
        let Some((_env, pool, owner, team)) = self_hosted_team().await else {
            return;
        };
        let policy = doc(json!({"security.lockTimeoutMinutes": {"$range": {"max": 20}}}));
        sqlx::query(
            "UPDATE teams SET policy = $2, lock_max_minutes = 60, lock_force_vault = TRUE WHERE id = $1",
        )
        .bind(team)
        .bind(&policy)
        .execute(&pool)
        .await
        .unwrap();

        let t = listed(&pool, team, owner).await;
        assert_eq!(
            t.lock_policy,
            Some(LockPolicy {
                max_minutes: 15,
                force_vault: false
            })
        );

        assert_eq!(
            put_status(&pool, team, owner, policy, 0).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(lock_columns(&pool, team).await, (Some(15), false));
    }
}
