use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use tracing::{error, info};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::enrollment::{mint_secret, normalize_domains};
use crate::rate_limit::{check_user_budget, GrantMintRateLimiter};
use crate::routes::audit::write_audit_event;
use crate::routes::ApiError;
use crate::routes::team_grants::{require_grant_admin, require_grantable_role};
use crate::session_grants::hash_secret;
use crate::team_authority::lock_billing_owner;
use crate::team_plan::require_granular;

fn internal(what: &'static str) -> impl FnOnce(sqlx::Error) -> ApiError {
    move |e| {
        error!(error = %e, "{what}");
        StatusCode::INTERNAL_SERVER_ERROR.into()
    }
}

async fn revoke_live(conn: &mut PgConnection, team_id: Uuid) -> Result<Option<Uuid>, ApiError> {
    sqlx::query_scalar::<_, Uuid>(
        "UPDATE team_enrollment_tokens SET revoked_at = now() WHERE team_id = $1 AND revoked_at IS NULL RETURNING id",
    )
    .bind(team_id)
    .fetch_optional(conn)
    .await
    .map_err(internal("Failed to revoke enrollment token"))
}

async fn audit(pool: &PgPool, team_id: Uuid, actor: Uuid, action: &str, token_id: Uuid, metadata: Option<serde_json::Value>) {
    write_audit_event(
        pool.clone(),
        team_id,
        actor,
        action,
        Some("enrollment_token"),
        Some(token_id.to_string()),
        None,
        metadata,
    )
    .await;
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub role: String,
    pub allowed_domains: Vec<String>,
    pub require_approval: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub secret: String,
    pub role: String,
    pub allowed_domains: Vec<String>,
    pub require_approval: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for CreateTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateTokenResponse")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("role", &self.role)
            .field("allowed_domains", &self.allowed_domains)
            .field("require_approval", &self.require_approval)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

fn validated_domains(body: &CreateTokenRequest) -> Result<Vec<String>, ApiError> {
    let domains = normalize_domains(&body.allowed_domains).map_err(|()| ApiError::from(StatusCode::BAD_REQUEST))?;
    if domains.is_empty() && !body.require_approval {
        return Err(ApiError::coded(StatusCode::BAD_REQUEST, "ENROLLMENT_NEEDS_GUARD"));
    }
    if !body.require_approval && !crate::email::delivery_configured() {
        return Err(ApiError::coded(StatusCode::BAD_REQUEST, "ENROLLMENT_NEEDS_APPROVAL"));
    }
    if body.expires_at.is_some_and(|at| at <= Utc::now()) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    Ok(domains)
}

pub async fn create_token(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(GrantMintRateLimiter(limiter)): Extension<GrantMintRateLimiter>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    check_user_budget(&limiter, auth.0, "enrollment_token_mint").await?;
    require_grant_admin(&pool, team_id, auth.0).await?;
    require_grantable_role(&pool, team_id, auth.0, &body.role).await?;
    let domains = validated_domains(&body)?;
    require_granular(&pool, team_id, false).await?;

    let secret = mint_secret();
    let mut tx = pool.begin().await.map_err(internal("Failed to begin enrollment token transaction"))?;
    lock_billing_owner(&mut tx, team_id).await?;
    let replaced = revoke_live(&mut tx, team_id).await?;
    let (id, created_at) = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
        "INSERT INTO team_enrollment_tokens \
         (team_id, secret_hash, role, allowed_domains, require_approval, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at",
    )
    .bind(team_id)
    .bind(hash_secret(&secret))
    .bind(&body.role)
    .bind(&domains)
    .bind(body.require_approval)
    .bind(body.expires_at)
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal("Failed to insert enrollment token"))?;
    tx.commit().await.map_err(internal("Failed to commit enrollment token"))?;

    info!(team_id = %team_id, token_id = %id, rotated = replaced.is_some(), "Enrollment token created");
    let action = if replaced.is_some() { "enrollment_token.rotated" } else { "enrollment_token.created" };
    let metadata = json!({
        "role": body.role,
        "allowed_domains": domains,
        "require_approval": body.require_approval,
        "expires_at": body.expires_at,
    });
    audit(&pool, team_id, auth.0, action, id, Some(metadata)).await;

    Ok((
        StatusCode::CREATED,
        Json(CreateTokenResponse {
            id,
            secret,
            role: body.role,
            allowed_domains: domains,
            require_approval: body.require_approval,
            expires_at: body.expires_at,
            created_at,
        }),
    ))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TokenView {
    pub id: Uuid,
    pub role: String,
    pub allowed_domains: Vec<String>,
    pub require_approval: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by_name: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub admitted_count: i64,
    pub pending_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GetTokenResponse {
    pub token: Option<TokenView>,
}

pub async fn get_token(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<GetTokenResponse>, ApiError> {
    require_grant_admin(&pool, team_id, auth.0).await?;
    let token = sqlx::query_as::<_, TokenView>(
        "SELECT t.id, t.role, t.allowed_domains, t.require_approval, t.expires_at, t.created_at, \
                u.handle AS created_by_name, t.last_used_at, \
                (SELECT count(*) FROM team_join_requests r WHERE r.token_id = t.id AND r.status = 'approved') AS admitted_count, \
                (SELECT count(*) FROM team_join_requests r WHERE r.token_id = t.id AND r.status = 'pending') AS pending_count \
         FROM team_enrollment_tokens t LEFT JOIN users u ON u.id = t.created_by \
         WHERE t.team_id = $1 AND t.revoked_at IS NULL",
    )
    .bind(team_id)
    .fetch_optional(&pool)
    .await
    .map_err(internal("Failed to read enrollment token"))?;
    Ok(Json(GetTokenResponse { token }))
}

pub async fn revoke_token(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_grant_admin(&pool, team_id, auth.0).await?;
    let mut conn = pool.acquire().await.map_err(internal("Failed to acquire connection"))?;
    let revoked = revoke_live(&mut conn, team_id).await?;
    if let Some(id) = revoked {
        info!(team_id = %team_id, token_id = %id, "Enrollment token revoked");
        audit(&pool, team_id, auth.0, "enrollment_token.revoked", id, None).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::Features;
    use crate::permissions::{PERM_CONNECT, PERM_INVITE_MEMBERS};
    use crate::rate_limit::RateLimiter;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        add_member, grant_builtin_role, member_with_role, seed_team_with_roles, seed_user, set_user_tier,
        team_audit_count, BillingMode,
    };
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;
    use tower::ServiceExt;

    fn budget() -> GrantMintRateLimiter {
        GrantMintRateLimiter(RateLimiter::new(100, Duration::from_secs(3600)))
    }

    async fn team_with_manager(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let owner = seed_user(pool).await;
        let team = seed_team_with_roles(pool, owner).await;
        let manager = seed_user(pool).await;
        add_member(pool, team, manager).await;
        grant_builtin_role(pool, team, manager, "manager").await;
        (team, owner, manager)
    }

    fn body(role: &str, domains: &[&str], approval: bool) -> CreateTokenRequest {
        CreateTokenRequest {
            role: role.to_string(),
            allowed_domains: domains.iter().map(|d| d.to_string()).collect(),
            require_approval: approval,
            expires_at: None,
        }
    }

    async fn create(
        pool: &PgPool,
        team: Uuid,
        actor: Uuid,
        req: CreateTokenRequest,
    ) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
        create_token(
            State(pool.clone()),
            Extension(AuthUser(actor)),
            Extension(budget()),
            Path(team),
            Json(req),
        )
        .await
    }

    async fn created(pool: &PgPool, team: Uuid, actor: Uuid, req: CreateTokenRequest) -> CreateTokenResponse {
        let (status, Json(token)) = create(pool, team, actor, req).await.expect("create token");
        assert_eq!(status, StatusCode::CREATED);
        token
    }

    async fn fetch(pool: &PgPool, team: Uuid, actor: Uuid) -> serde_json::Value {
        let Json(value) = get_token(State(pool.clone()), Extension(AuthUser(actor)), Path(team))
            .await
            .expect("get token");
        serde_json::to_value(value).unwrap()
    }

    async fn revoke(pool: &PgPool, team: Uuid, actor: Uuid) -> Result<StatusCode, ApiError> {
        revoke_token(State(pool.clone()), Extension(AuthUser(actor)), Path(team)).await
    }

    fn error_code(err: ApiError) -> (StatusCode, Option<&'static str>) {
        (err.0, err.1)
    }

    async fn business_team(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let (team, owner, manager) = team_with_manager(pool).await;
        set_user_tier(pool, owner, "business").await;
        (team, owner, manager)
    }

    #[tokio::test]
    async fn create_returns_secret_once_and_get_never_does() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;

        let token = created(&pool, team, manager, body("member", &["Example.com"], true)).await;
        assert_eq!(token.secret.len(), 43);
        assert_eq!(token.allowed_domains, vec!["example.com".to_string()]);
        assert!(!format!("{token:?}").contains(&token.secret));

        let stored: Vec<u8> = sqlx::query_scalar("SELECT secret_hash FROM team_enrollment_tokens WHERE id = $1")
            .bind(token.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, crate::session_grants::hash_secret(&token.secret));

        let view = fetch(&pool, team, manager).await;
        let live = &view["token"];
        assert_eq!(live["id"], token.id.to_string());
        assert_eq!(live["role"], "member");
        assert_eq!(live["admitted_count"], 0);
        assert_eq!(live["pending_count"], 0);
        assert!(live["created_by_name"].is_string());
        assert!(!view.to_string().contains(&token.secret));
        assert!(live.get("secret").is_none());
    }

    #[tokio::test]
    async fn get_counts_admitted_and_pending_for_the_live_token() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        assert!(fetch(&pool, team, manager).await["token"].is_null());

        let token = created(&pool, team, manager, body("member", &[], true)).await;
        for status in ["approved", "approved", "pending"] {
            let user = seed_user(&pool).await;
            sqlx::query("INSERT INTO team_join_requests (team_id, user_id, token_id, status) VALUES ($1, $2, $3, $4)")
                .bind(team)
                .bind(user)
                .bind(token.id)
                .bind(status)
                .execute(&pool)
                .await
                .unwrap();
        }
        let view = fetch(&pool, team, manager).await;
        assert_eq!(view["token"]["admitted_count"], 2);
        assert_eq!(view["token"]["pending_count"], 1);
    }

    #[tokio::test]
    async fn create_without_guard_is_400_needs_guard() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let err = create(&pool, team, manager, body("member", &[], false)).await.unwrap_err();
        assert_eq!(error_code(err), (StatusCode::BAD_REQUEST, Some("ENROLLMENT_NEEDS_GUARD")));
    }

    #[tokio::test]
    async fn create_without_approval_on_server_without_email_is_400_needs_approval() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let previous = std::env::var("RESEND_API_KEY").ok();
        std::env::remove_var("RESEND_API_KEY");

        let without = create(&pool, team, manager, body("member", &["example.com"], false)).await;
        let with = create(&pool, team, manager, body("member", &["example.com"], true)).await;

        if let Some(v) = previous {
            std::env::set_var("RESEND_API_KEY", v);
        }
        assert_eq!(
            error_code(without.unwrap_err()),
            (StatusCode::BAD_REQUEST, Some("ENROLLMENT_NEEDS_APPROVAL"))
        );
        assert!(with.is_ok());
    }

    #[tokio::test]
    async fn domains_without_approval_are_allowed_when_email_is_configured() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let previous = std::env::var("RESEND_API_KEY").ok();
        std::env::set_var("RESEND_API_KEY", "test-key");

        let result = create(&pool, team, manager, body("member", &["example.com"], false)).await;

        match previous {
            Some(v) => std::env::set_var("RESEND_API_KEY", v),
            None => std::env::remove_var("RESEND_API_KEY"),
        }
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn invalid_domains_role_and_expiry_are_400() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;

        let bad_domain = create(&pool, team, manager, body("member", &["a@b.com"], true)).await.unwrap_err();
        assert_eq!(bad_domain.0, StatusCode::BAD_REQUEST);

        let mut past = body("member", &[], true);
        past.expires_at = Some(Utc::now() - chrono::Duration::minutes(1));
        assert_eq!(create(&pool, team, manager, past).await.unwrap_err().0, StatusCode::BAD_REQUEST);

        let mut future = body("member", &[], true);
        future.expires_at = Some(Utc::now() + chrono::Duration::days(1));
        assert!(create(&pool, team, manager, future).await.is_ok());
    }

    #[tokio::test]
    async fn create_owner_role_is_400() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, owner, _manager) = team_with_manager(&pool).await;
        for role in ["owner", "no-such-role"] {
            let err = create(&pool, team, owner, body(role, &[], true)).await.unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn create_role_above_actor_is_403() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, _manager) = team_with_manager(&pool).await;
        let inviter = crate::test_support::inviter_with(&pool, team, PERM_INVITE_MEMBERS).await;
        let err = create(&pool, team, inviter, body("manager", &[], true)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_without_invite_permission_is_403() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let plain = member_with_role(&pool, team, PERM_CONNECT).await;
        created(&pool, team, manager, body("member", &[], true)).await;

        for actor in [plain, seed_user(&pool).await] {
            assert_eq!(create(&pool, team, actor, body("member", &[], true)).await.unwrap_err().0, StatusCode::FORBIDDEN);
            assert_eq!(
                get_token(State(pool.clone()), Extension(AuthUser(actor)), Path(team)).await.unwrap_err().0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(revoke(&pool, team, actor).await.unwrap_err().0, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn rotate_revokes_previous_and_old_secret_hash_is_dead() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;

        let first = created(&pool, team, manager, body("member", &[], true)).await;
        let second = created(&pool, team, manager, body("editor", &["example.com"], true)).await;
        assert_ne!(first.id, second.id);
        assert_ne!(first.secret, second.secret);

        let live: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM team_enrollment_tokens WHERE team_id = $1 AND revoked_at IS NULL",
        )
        .bind(team)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(live, vec![second.id]);

        let old_live: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM team_enrollment_tokens WHERE secret_hash = $1 AND revoked_at IS NULL",
        )
        .bind(crate::session_grants::hash_secret(&first.secret))
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(old_live, None);
        assert_eq!(fetch(&pool, team, manager).await["token"]["role"], "editor");
    }

    #[tokio::test]
    async fn below_business_create_402_revoke_204() {
        let _billing = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let (team, owner, manager) = business_team(&pool).await;
        let token = created(&pool, team, manager, body("member", &[], true)).await;

        set_user_tier(&pool, owner, "free").await;
        let err = create(&pool, team, manager, body("member", &[], true)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(fetch(&pool, team, manager).await["token"]["id"], token.id.to_string());

        assert_eq!(revoke(&pool, team, manager).await.unwrap(), StatusCode::NO_CONTENT);
        assert!(fetch(&pool, team, manager).await["token"].is_null());
        assert_eq!(revoke(&pool, team, manager).await.unwrap(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn team_invites_disabled_blocks_all_routes() {
        let app = axum::Router::new()
            .route(
                "/v1/teams/:team_id/enrollment-token",
                axum::routing::post(create_token)
                    .get(get_token)
                    .delete(revoke_token)
                    .layer(axum::middleware::from_fn(crate::features::require_team_invites)),
            )
            .layer(Extension(Features { team_invites: false, ..Features::open() }))
            .with_state(crate::test_support::dead_pool().await);

        for method in ["POST", "GET", "DELETE"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("/v1/teams/{}/enrollment-token", Uuid::new_v4()))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method}");
        }
    }

    #[tokio::test]
    async fn audit_created_rotated_revoked() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;

        created(&pool, team, manager, body("member", &[], true)).await;
        assert_eq!(team_audit_count(&pool, team, "enrollment_token.created").await, 1);
        assert_eq!(team_audit_count(&pool, team, "enrollment_token.rotated").await, 0);

        created(&pool, team, manager, body("member", &["example.com"], true)).await;
        assert_eq!(team_audit_count(&pool, team, "enrollment_token.created").await, 1);
        assert_eq!(team_audit_count(&pool, team, "enrollment_token.rotated").await, 1);

        revoke(&pool, team, manager).await.unwrap();
        revoke(&pool, team, manager).await.unwrap();
        assert_eq!(team_audit_count(&pool, team, "enrollment_token.revoked").await, 1);

        let metadata: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM audit_logs WHERE team_id = $1 AND action = 'enrollment_token.rotated'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(metadata["role"], "member");
        assert_eq!(metadata["allowed_domains"], serde_json::json!(["example.com"]));
        assert_eq!(metadata["require_approval"], true);
    }

    #[tokio::test]
    async fn two_simultaneous_creates_leave_one_live_token() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = team_with_manager(&pool).await;

        let (a, b) = tokio::join!(
            create(&pool, team, manager, body("member", &[], true)),
            create(&pool, team, manager, body("editor", &[], true)),
        );
        assert!(a.is_ok() && b.is_ok());

        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM team_enrollment_tokens WHERE team_id = $1 AND revoked_at IS NULL",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(live, 1);
    }
}
