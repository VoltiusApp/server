use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::routes::audit::write_audit_event;
use crate::routes::teams::{notify_team_members_changed, require_vault_manager};
use crate::sync_notifier::SyncNotifier;
use crate::team_plan::require_granular;

const LOCK_MINUTES: [i32; 6] = [0, 5, 15, 30, 60, 240];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockPolicy {
    pub max_minutes: i32,
    pub force_vault: bool,
}

impl LockPolicy {
    pub fn from_columns(max_minutes: Option<i32>, force_vault: bool) -> Option<Self> {
        max_minutes.map(|max_minutes| Self {
            max_minutes,
            force_vault,
        })
    }
}

pub async fn set_lock_policy(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<LockPolicy>,
) -> Result<StatusCode, StatusCode> {
    require_vault_manager(&pool, team_id, auth.0).await?;
    if !LOCK_MINUTES.contains(&body.max_minutes) {
        return Err(StatusCode::BAD_REQUEST);
    }
    require_granular(&pool, team_id, false).await?;
    write_policy(&pool, &notifier, team_id, auth.0, Some(body)).await
}

pub async fn clear_lock_policy(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    require_vault_manager(&pool, team_id, auth.0).await?;
    require_granular(&pool, team_id, true).await?;
    write_policy(&pool, &notifier, team_id, auth.0, None).await
}

async fn write_policy(
    pool: &PgPool,
    notifier: &SyncNotifier,
    team_id: Uuid,
    actor: Uuid,
    policy: Option<LockPolicy>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE teams SET lock_max_minutes = $2, lock_force_vault = $3 WHERE id = $1")
        .bind(team_id)
        .bind(policy.map(|p| p.max_minutes))
        .bind(policy.is_some_and(|p| p.force_vault))
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, "Failed to write team lock policy");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let (action, metadata) = match policy {
        Some(p) => ("team.lock_policy_set", Some(json!(p))),
        None => ("team.lock_policy_removed", None),
    };
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
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{PERM_MANAGE_MEMBERS, PERM_MANAGE_VAULT};
    use crate::routes::teams::list_teams;
    use crate::sync_notifier::SyncEvent;
    use crate::test_support::{
        member_with_role, seed_team_with_roles, seed_user, set_user_tier, BillingMode,
    };

    async fn listed(pool: &PgPool, team: Uuid, user: Uuid) -> Option<LockPolicy> {
        let Json(teams) = list_teams(State(pool.clone()), Extension(AuthUser(user)))
            .await
            .unwrap();
        teams
            .into_iter()
            .find(|t| t.id == team)
            .unwrap()
            .lock_policy
    }

    #[tokio::test]
    async fn list_teams_carries_the_stored_policy() {
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        assert_eq!(listed(&pool, team, owner).await, None);

        sqlx::query(
            "UPDATE teams SET lock_max_minutes = 15, lock_force_vault = TRUE WHERE id = $1",
        )
        .bind(team)
        .execute(&pool)
        .await
        .unwrap();

        assert_eq!(
            listed(&pool, team, owner).await,
            Some(LockPolicy {
                max_minutes: 15,
                force_vault: true
            })
        );
    }

    async fn put(
        pool: &PgPool,
        team: Uuid,
        user: Uuid,
        max_minutes: i32,
        force_vault: bool,
    ) -> Result<StatusCode, StatusCode> {
        set_lock_policy(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(LockPolicy {
                max_minutes,
                force_vault,
            }),
        )
        .await
    }

    async fn clear(pool: &PgPool, team: Uuid, user: Uuid) -> Result<StatusCode, StatusCode> {
        clear_lock_policy(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(SyncNotifier::new()),
            Path(team),
        )
        .await
    }

    async fn audit_count(pool: &PgPool, team: Uuid, action: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE team_id = $1 AND action = $2")
            .bind(team)
            .bind(action)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn owner_sets_and_clears_the_policy_every_member_lists() {
        let _env = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;

        assert_eq!(
            put(&pool, team, owner, 15, true).await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            listed(&pool, team, member).await,
            Some(LockPolicy {
                max_minutes: 15,
                force_vault: true
            })
        );
        assert_eq!(audit_count(&pool, team, "team.lock_policy_set").await, 1);

        assert_eq!(clear(&pool, team, owner).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(listed(&pool, team, member).await, None);
        assert_eq!(
            audit_count(&pool, team, "team.lock_policy_removed").await,
            1
        );
        assert_eq!(clear(&pool, team, owner).await, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn only_values_from_the_auto_lock_list_are_accepted() {
        let _env = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;

        for bad in [-1, 1, 7, 241, 1440] {
            assert_eq!(
                put(&pool, team, owner, bad, false).await,
                Err(StatusCode::BAD_REQUEST),
                "{bad}"
            );
        }
        for good in [0, 5, 15, 30, 60, 240] {
            assert_eq!(
                put(&pool, team, owner, good, false).await,
                Ok(StatusCode::NO_CONTENT),
                "{good}"
            );
        }
        assert_eq!(
            listed(&pool, team, owner).await,
            Some(LockPolicy {
                max_minutes: 240,
                force_vault: false
            })
        );
    }

    #[tokio::test]
    async fn writing_the_policy_needs_manage_vault() {
        let _env = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let manager = member_with_role(&pool, team, PERM_MANAGE_VAULT).await;
        let outsider = seed_user(&pool).await;

        assert_eq!(
            put(&pool, team, member, 15, false).await,
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            put(&pool, team, outsider, 15, false).await,
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(clear(&pool, team, member).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(
            put(&pool, team, manager, 30, false).await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[tokio::test]
    async fn below_business_the_policy_stays_and_can_only_be_removed() {
        let _env = BillingMode::hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "teams").await;
        let team = seed_team_with_roles(&pool, owner).await;
        sqlx::query("UPDATE teams SET lock_max_minutes = 5 WHERE id = $1")
            .bind(team)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            put(&pool, team, owner, 15, false).await,
            Err(StatusCode::PAYMENT_REQUIRED)
        );
        assert_eq!(
            listed(&pool, team, owner).await,
            Some(LockPolicy {
                max_minutes: 5,
                force_vault: false
            })
        );
        assert_eq!(clear(&pool, team, owner).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(listed(&pool, team, owner).await, None);
    }

    #[tokio::test]
    async fn a_business_team_can_set_the_policy_when_hosted() {
        let _env = BillingMode::hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "business").await;
        let team = seed_team_with_roles(&pool, owner).await;

        assert_eq!(
            put(&pool, team, owner, 60, true).await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[tokio::test]
    async fn every_member_is_told_the_team_changed() {
        let _env = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        set_lock_policy(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(notifier),
            Path(team),
            Json(LockPolicy {
                max_minutes: 15,
                force_vault: false,
            }),
        )
        .await
        .unwrap();

        let want = format!("team_members:{team}");
        let mut told = std::collections::HashSet::new();
        while let Ok(ev) = rx.try_recv() {
            if let SyncEvent::BlobPushed { user_id, device_id } = ev {
                if device_id == want {
                    told.insert(user_id);
                }
            }
        }
        assert!(told.contains(&owner) && told.contains(&member));
    }
}
