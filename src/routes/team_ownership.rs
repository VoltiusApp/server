use axum::{extract::{Path, State}, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::entitlement::effective_tier_for_user;
use crate::routes::audit::write_audit_event;
use crate::routes::teams::{notify_team_members_changed, owner_seat_cap};
use crate::self_host;
use crate::sync_notifier::SyncNotifier;
use crate::team_authority::{holds_owner_role, lock_billing_owner};

#[derive(Deserialize)]
pub struct TransferBillingOwnerRequest {
    pub user_id: Uuid,
}

fn plan_rank(tier: &str) -> u8 {
    match tier {
        "business" => 2,
        "teams" => 1,
        _ => 0,
    }
}

/// 402 unless `target`'s own subscription can carry this team at its current plan and size.
async fn ensure_target_can_pay(pool: &PgPool, team_id: Uuid, current: Uuid, target: Uuid) -> Result<(), StatusCode> {
    let needed = plan_rank(&effective_tier_for_user(pool, current).await).max(1);
    if plan_rank(&effective_tier_for_user(pool, target).await) < needed {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }
    let Some(cap) = owner_seat_cap(pool, target).await? else {
        return Ok(());
    };
    let seats_after = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT tm.user_id) FROM team_members tm JOIN teams t ON t.id = tm.team_id \
         WHERE t.owner_id = $1 OR t.id = $2",
    )
    .bind(target)
    .bind(team_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to count seats for billing transfer");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if seats_after > cap {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }
    Ok(())
}

/// Hand the team's billing to another Owner. On a self-hosted server any Owner may move it.
pub async fn transfer_billing_owner(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<TransferBillingOwnerRequest>,
) -> Result<StatusCode, StatusCode> {
    let self_hosted = self_host::is_self_hosted();
    let db = |e: sqlx::Error| {
        error!(error = %e, team_id = %team_id, "Failed to transfer billing owner");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let mut tx = pool.begin().await.map_err(db)?;
    let current = lock_billing_owner(&mut tx, team_id).await?;
    let may_transfer = auth.0 == current || (self_hosted && holds_owner_role(&mut *tx, team_id, auth.0).await?);
    if !may_transfer {
        warn!(team_id = %team_id, user_id = %auth.0, "Refused billing transfer by a non-billing owner");
        return Err(StatusCode::FORBIDDEN);
    }
    if body.user_id == current {
        return Ok(StatusCode::NO_CONTENT);
    }
    if !holds_owner_role(&mut *tx, team_id, body.user_id).await? {
        return Err(StatusCode::CONFLICT);
    }
    if !self_hosted {
        ensure_target_can_pay(&pool, team_id, current, body.user_id).await?;
    }
    sqlx::query("UPDATE teams SET owner_id = $2 WHERE id = $1")
        .bind(team_id)
        .bind(body.user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;

    info!(team_id = %team_id, from = %current, to = %body.user_id, "Billing owner transferred");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "team.billing_owner_changed",
        Some("user"),
        Some(body.user_id.to_string()),
        None,
        Some(json!({ "from": current, "to": body.user_id })),
    ));
    crate::team_plan::after_billing_owner_change(&pool, &notifier, team_id, current, body.user_id).await?;
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::*;

    async fn transfer(pool: &PgPool, actor: Uuid, team: Uuid, to: Uuid) -> Result<StatusCode, StatusCode> {
        transfer_billing_owner(
            State(pool.clone()),
            Extension(AuthUser(actor)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(TransferBillingOwnerRequest { user_id: to }),
        )
        .await
    }

    async fn billing_owner(pool: &PgPool, team: Uuid) -> Uuid {
        sqlx::query_scalar("SELECT owner_id FROM teams WHERE id = $1").bind(team).fetch_one(pool).await.unwrap()
    }

    async fn co_owner(pool: &PgPool, team: Uuid) -> Uuid {
        let user = seed_user(pool).await;
        add_member(pool, team, user).await;
        grant_builtin_role(pool, team, user, "owner").await;
        user
    }

    #[tokio::test]
    async fn self_hosted_any_owner_can_take_billing() {
        let _mode = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let creator = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, creator).await;
        let bob = co_owner(&pool, team).await;

        assert_eq!(transfer(&pool, bob, team, bob).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(billing_owner(&pool, team).await, bob);
    }

    #[tokio::test]
    async fn hosted_only_the_billing_owner_can_transfer() {
        let _mode = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let creator = seed_user(&pool).await;
        set_user_tier(&pool, creator, "teams").await;
        let team = seed_team_with_roles(&pool, creator).await;
        let bob = co_owner(&pool, team).await;
        set_user_tier(&pool, bob, "teams").await;

        assert_eq!(transfer(&pool, bob, team, bob).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(transfer(&pool, creator, team, bob).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(billing_owner(&pool, team).await, bob);
    }

    #[tokio::test]
    async fn the_target_must_already_be_an_owner() {
        let _mode = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let creator = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, creator).await;
        let manager = seed_user(&pool).await;
        add_member(&pool, team, manager).await;
        grant_builtin_role(&pool, team, manager, "manager").await;

        assert_eq!(transfer(&pool, creator, team, manager).await, Err(StatusCode::CONFLICT));
        assert_eq!(billing_owner(&pool, team).await, creator);
    }

    #[tokio::test]
    async fn hosted_target_needs_a_plan_at_least_as_high() {
        let _mode = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let creator = seed_user(&pool).await;
        set_user_tier(&pool, creator, "business").await;
        let team = seed_team_with_roles(&pool, creator).await;
        let bob = co_owner(&pool, team).await;

        for tier in ["free", "pro", "teams"] {
            set_user_tier(&pool, bob, tier).await;
            assert_eq!(transfer(&pool, creator, team, bob).await, Err(StatusCode::PAYMENT_REQUIRED), "{tier}");
        }
        set_user_tier(&pool, bob, "business").await;
        assert_eq!(transfer(&pool, creator, team, bob).await, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn hosted_target_needs_seats_for_their_teams_plus_this_one() {
        let _mode = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let creator = seed_user(&pool).await;
        set_user_tier(&pool, creator, "teams").await;
        let team = seed_team_with_roles(&pool, creator).await;
        let bob = co_owner(&pool, team).await;
        set_user_tier(&pool, bob, "teams").await;
        let bobs_team = seed_team_with_roles(&pool, bob).await;
        let other = seed_user(&pool).await;
        add_member(&pool, bobs_team, other).await;

        set_user_seats(&pool, bob, 2).await;
        assert_eq!(transfer(&pool, creator, team, bob).await, Err(StatusCode::PAYMENT_REQUIRED));
        set_user_seats(&pool, bob, 3).await;
        assert_eq!(transfer(&pool, creator, team, bob).await, Ok(StatusCode::NO_CONTENT));
    }
}
