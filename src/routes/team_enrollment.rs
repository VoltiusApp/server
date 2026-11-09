use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use tracing::{error, info};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::enrollment::{
    audit_request, decide_pending, mint_secret, normalize_domains, notify_join_requests_changed, redeem_for, try_admit,
    Guard, RedeemOutcome, role_or_default,
};
use crate::rate_limit::{check_budget, ClientIp, EnrollmentRedeemRateLimiter, EnrollmentResolveLimiter, GrantMintRateLimiter};
use crate::routes::audit::write_audit_event;
use crate::routes::ApiError;
use crate::routes::team_grants::{require_grant_admin, require_grantable_role, validate_public_key};
use crate::session_grants::hash_secret;
use crate::sync_notifier::SyncNotifier;
use crate::team_authority::{lock_billing_owner, require_may_confer_builtin};
use crate::team_plan::{require_granular, team_locked};

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
    check_budget(&limiter, auth.0, "enrollment_token_mint").await?;
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

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct TokenRow {
    pub id: Uuid,
    pub team_id: Uuid,
    pub team_name: String,
    pub allowed_domains: Vec<String>,
    pub require_approval: bool,
}

impl TokenRow {
    pub(crate) fn guard(&self) -> Guard {
        Guard { allowed_domains: self.allowed_domains.clone(), require_approval: self.require_approval }
    }
}

#[derive(Debug)]
pub(crate) enum EnrollError {
    NotFound,
    Gone,
    Unavailable,
    DomainMismatch,
    NoSeat,
    MissingKey,
    Internal,
}

impl From<sqlx::Error> for EnrollError {
    fn from(e: sqlx::Error) -> Self {
        error!(error = %e, "Enrollment query failed");
        EnrollError::Internal
    }
}

impl From<StatusCode> for EnrollError {
    fn from(status: StatusCode) -> Self {
        error!(%status, "Enrollment dependency failed");
        EnrollError::Internal
    }
}

impl From<EnrollError> for ApiError {
    fn from(err: EnrollError) -> Self {
        match err {
            EnrollError::NotFound => StatusCode::NOT_FOUND.into(),
            EnrollError::Gone => StatusCode::GONE.into(),
            EnrollError::Unavailable => ApiError::coded(StatusCode::PAYMENT_REQUIRED, "ENROLLMENT_UNAVAILABLE"),
            EnrollError::DomainMismatch => ApiError::coded(StatusCode::FORBIDDEN, "ENROLLMENT_DOMAIN_MISMATCH"),
            EnrollError::NoSeat => StatusCode::PAYMENT_REQUIRED.into(),
            EnrollError::MissingKey => StatusCode::BAD_REQUEST.into(),
            EnrollError::Internal => StatusCode::INTERNAL_SERVER_ERROR.into(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct LiveTokenLookup {
    #[sqlx(flatten)]
    row: TokenRow,
    revoked: bool,
    expired: bool,
}

pub(crate) async fn load_live_token(pool: &PgPool, id: Uuid, secret: &str) -> Result<TokenRow, EnrollError> {
    let found = sqlx::query_as::<_, LiveTokenLookup>(
        "SELECT t.id, t.team_id, tm.name AS team_name, t.allowed_domains, t.require_approval, \
                t.revoked_at IS NOT NULL AS revoked, COALESCE(t.expires_at <= now(), false) AS expired \
         FROM team_enrollment_tokens t JOIN teams tm ON tm.id = t.team_id \
         WHERE t.id = $1 AND t.secret_hash = $2",
    )
    .bind(id)
    .bind(hash_secret(secret))
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to load enrollment token");
        EnrollError::Internal
    })?
    .ok_or(EnrollError::NotFound)?;
    if found.revoked || found.expired {
        return Err(EnrollError::Gone);
    }
    match team_locked(pool, found.row.team_id).await {
        Ok(false) => Ok(found.row),
        Ok(true) => Err(EnrollError::Unavailable),
        Err(_) => Err(EnrollError::Internal),
    }
}

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub id: Uuid,
    pub secret: String,
}

pub async fn resolve(
    State(pool): State<PgPool>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(EnrollmentResolveLimiter(limiter)): Extension<EnrollmentResolveLimiter>,
    Json(body): Json<ResolveRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_budget(&limiter, ip, "enrollment_resolve").await?;
    let token = load_live_token(&pool, body.id, &body.secret).await?;
    Ok(Json(json!({
        "team_name": token.team_name,
        "allowed_domains": token.allowed_domains,
        "require_approval": token.require_approval,
        "registration_open": true,
    })))
}

#[derive(Deserialize)]
pub struct RedeemRequest {
    pub id: Uuid,
    pub secret: String,
    pub public_key: Option<String>,
}

pub async fn redeem(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Extension(EnrollmentRedeemRateLimiter(limiter)): Extension<EnrollmentRedeemRateLimiter>,
    Json(body): Json<RedeemRequest>,
) -> Result<Json<RedeemOutcome>, ApiError> {
    check_budget(&limiter, auth.0, "enrollment_redeem").await?;
    validate_public_key(body.public_key.as_deref())?;
    let token = load_live_token(&pool, body.id, &body.secret).await?;
    Ok(Json(redeem_for(&pool, &notifier, &token, auth.0, body.public_key.as_deref()).await?))
}

#[derive(Deserialize)]
pub struct ListRequestsQuery {
    pub status: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JoinRequestView {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub reason: Option<String>,
    pub email_proven: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn list_requests(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Query(query): Query<ListRequestsQuery>,
) -> Result<Json<Vec<JoinRequestView>>, ApiError> {
    require_grant_admin(&pool, team_id, auth.0).await?;
    let status = query.status.unwrap_or_else(|| "pending".to_string());
    if !["pending", "approved", "denied"].contains(&status.as_str()) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let rows = sqlx::query_as::<_, JoinRequestView>(
        "SELECT r.id, r.user_id, u.email, u.handle AS display_name, r.reason, u.email_proven_at IS NOT NULL AS email_proven, r.created_at \
         FROM team_join_requests r JOIN users u ON u.id = r.user_id \
         WHERE r.team_id = $1 AND r.status = $2 ORDER BY r.created_at, r.id",
    )
    .bind(team_id)
    .bind(status)
    .fetch_all(&pool)
    .await
    .map_err(internal("Failed to list join requests"))?;
    Ok(Json(rows))
}

pub async fn approve(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path((team_id, request_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RedeemOutcome>, ApiError> {
    require_grant_admin(&pool, team_id, auth.0).await?;
    let role = sqlx::query_scalar::<_, Option<String>>(
        "SELECT t.role FROM team_join_requests r \
         LEFT JOIN team_enrollment_tokens t ON t.id = r.token_id \
         WHERE r.id = $1 AND r.team_id = $2 AND r.status = 'pending'",
    )
    .bind(request_id)
    .bind(team_id)
    .fetch_optional(&pool)
    .await
    .map_err(internal("Failed to read join request"))?
    .ok_or(StatusCode::NOT_FOUND)?;
    require_may_confer_builtin(&pool, team_id, auth.0, role_or_default(role.as_deref())).await?;
    Ok(Json(try_admit(&pool, &notifier, request_id, Some(auth.0)).await?))
}

pub async fn deny(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path((team_id, request_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    require_grant_admin(&pool, team_id, auth.0).await?;
    let mut conn = pool.acquire().await.map_err(internal("Failed to acquire connection"))?;
    let user_id = decide_pending(&mut conn, request_id, team_id, "denied", Some(auth.0))
        .await
        .map_err(internal("Failed to deny join request"))?
        .ok_or(StatusCode::NOT_FOUND)?;
    drop(conn);
    audit_request(&pool, team_id, auth.0, "join_request.denied", request_id, user_id).await;
    notify_join_requests_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::Features;
    use crate::permissions::{PERM_CONNECT, PERM_INVITE_MEMBERS};
    use crate::enrollment::{try_admit, PendingReason};
    use crate::rate_limit::{EnrollmentRegisterLimiter, RateLimiter, RegisterRateLimiter};
    use crate::sync_notifier::SyncEvent;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        add_member, grant_builtin_role, member_with_role, seed_team_with_roles, seed_user, set_user_tier,
        team_audit_count, BillingMode,
    };
    use axum::body::Body;
    use axum::http::Request;
    use std::net::SocketAddr;
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

    struct SignupApp {
        app: axum::Router,
        pool: PgPool,
    }

    fn signup_app(pool: &PgPool, features: Features, register_per_day: usize) -> SignupApp {
        signup_app_with_token_budget(pool, features, register_per_day, 500)
    }

    fn signup_app_with_token_budget(pool: &PgPool, features: Features, register_per_day: usize, token_per_day: usize) -> SignupApp {
        std::env::set_var("JWT_SECRET", "ci-test-secret");
        let auth_limiter = RateLimiter::new(10, Duration::from_secs(60));
        let app = crate::signup_routes(
            crate::sync_notifier::SyncNotifier::new(),
            auth_limiter.clone(),
            RegisterRateLimiter(RateLimiter::new(register_per_day, Duration::from_secs(86400))),
            EnrollmentResolveLimiter(RateLimiter::new(60, Duration::from_secs(60))),
            EnrollmentRegisterLimiter(RateLimiter::new(token_per_day, Duration::from_secs(86400))),
        )
        .merge(
            axum::Router::new()
                .route("/v1/auth/login", axum::routing::post(|| async { StatusCode::OK }))
                .layer(axum::middleware::from_fn(crate::rate_limit::auth_rate_limit))
                .layer(Extension(auth_limiter)),
        )
        .layer(Extension(features))
        .with_state(pool.clone());
        SignupApp { app, pool: pool.clone() }
    }

    impl SignupApp {
        async fn post(&self, uri: &str, ip: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
            let mut req = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let addr = SocketAddr::new(ip.parse().unwrap(), 4000);
            req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
            let resp = self.app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
        }

        async fn resolve(&self, ip: &str, id: Uuid, secret: &str) -> (StatusCode, serde_json::Value) {
            self.post("/v1/enrollment/resolve", ip, json!({ "id": id, "secret": secret })).await
        }

        async fn register(&self, ip: &str, email: &str, enrollment: Option<(Uuid, &str)>) -> (StatusCode, serde_json::Value) {
            let mut body = json!({ "email": email, "account_id": Uuid::new_v4(), "auth_key": "auth-key-secret", "public_key": "pk" });
            if let Some((id, secret)) = enrollment {
                body["enrollment"] = json!({ "id": id, "secret": secret });
            }
            self.post("/v1/auth/register", ip, body).await
        }

        async fn register_raw(&self, ip: &str, body: &str) -> StatusCode {
            let mut req = Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap();
            req.extensions_mut().insert(axum::extract::ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 4000)));
            self.app.clone().oneshot(req).await.unwrap().status()
        }

        async fn user_exists(&self, email: &str) -> bool {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
                .bind(email)
                .fetch_one(&self.pool)
                .await
                .unwrap()
        }
    }

    fn fresh_email(domain: &str) -> String {
        format!("u{}@{domain}", Uuid::new_v4().simple())
    }

    async fn acme_token(pool: &PgPool) -> CreateTokenResponse {
        let (team, _owner, manager) = team_with_manager(pool).await;
        created(pool, team, manager, body("member", &["acme.com"], true)).await
    }

    #[tokio::test]
    async fn resolve_returns_team_name_and_guards() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let token = created(&pool, team, manager, body("member", &["acme.com"], true)).await;
        let name: String = sqlx::query_scalar("SELECT name FROM teams WHERE id = $1").bind(team).fetch_one(&pool).await.unwrap();

        let (status, value) = app.resolve("10.0.0.1", token.id, &token.secret).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            value,
            json!({
                "team_name": name,
                "allowed_domains": ["acme.com"],
                "require_approval": true,
                "registration_open": true,
            })
        );
    }

    #[tokio::test]
    async fn resolve_unknown_404_revoked_410_expired_410_lapsed_402() {
        let _billing = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        let (team, owner, manager) = business_team(&pool).await;
        let token = created(&pool, team, manager, body("member", &[], true)).await;

        assert_eq!(app.resolve("10.0.0.2", Uuid::new_v4(), &token.secret).await.0, StatusCode::NOT_FOUND);
        assert_eq!(app.resolve("10.0.0.2", token.id, "wrong-secret").await.0, StatusCode::NOT_FOUND);
        assert_eq!(app.resolve("10.0.0.2", token.id, &token.secret).await.0, StatusCode::OK);

        sqlx::query("UPDATE team_enrollment_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1")
            .bind(token.id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(app.resolve("10.0.0.2", token.id, &token.secret).await.0, StatusCode::GONE);

        let fresh = created(&pool, team, manager, body("member", &[], true)).await;
        set_user_tier(&pool, owner, "free").await;
        let (status, value) = app.resolve("10.0.0.2", fresh.id, &fresh.secret).await;
        assert_eq!((status, value), (StatusCode::PAYMENT_REQUIRED, json!({ "error": "ENROLLMENT_UNAVAILABLE" })));

        set_user_tier(&pool, owner, "business").await;
        revoke(&pool, team, manager).await.unwrap();
        assert_eq!(app.resolve("10.0.0.2", fresh.id, &fresh.secret).await.0, StatusCode::GONE);
    }

    #[tokio::test]
    async fn resolve_has_own_ip_bucket() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        for _ in 0..60 {
            assert_eq!(app.resolve("10.0.0.3", Uuid::new_v4(), "x").await.0, StatusCode::NOT_FOUND);
        }
        assert_eq!(app.resolve("10.0.0.3", Uuid::new_v4(), "x").await.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(app.post("/v1/auth/login", "10.0.0.3", json!({})).await.0, StatusCode::OK);
        assert_eq!(app.resolve("10.0.0.4", Uuid::new_v4(), "x").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn register_with_token_works_when_registration_disabled() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features { registration: false, ..Features::open() }, 5);
        let token = acme_token(&pool).await;
        let email = fresh_email("acme.com");
        let (status, _) = app.register("10.0.1.1", &email, Some((token.id, &token.secret))).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(app.user_exists(&email).await);
    }

    #[tokio::test]
    async fn register_without_token_still_blocked_when_disabled() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features { registration: false, ..Features::open() }, 5);
        let email = fresh_email("acme.com");
        let (status, value) = app.register("10.0.1.2", &email, None).await;
        assert_eq!((status, value), (StatusCode::FORBIDDEN, json!({ "error": "REGISTRATION_DISABLED" })));
        assert!(!app.user_exists(&email).await);
    }

    #[tokio::test]
    async fn register_with_token_skips_ip_daily_limit() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        let token = acme_token(&pool).await;
        for _ in 0..6 {
            let (status, _) = app.register("10.0.1.3", &fresh_email("acme.com"), Some((token.id, &token.secret))).await;
            assert_eq!(status, StatusCode::CREATED);
        }
        assert_eq!(app.register("10.0.1.3", &fresh_email("acme.com"), None).await.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn register_with_token_skips_shared_auth_bucket() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        let token = acme_token(&pool).await;
        for _ in 0..11 {
            let (status, _) = app.register("10.0.1.4", &fresh_email("acme.com"), Some((token.id, &token.secret))).await;
            assert_eq!(status, StatusCode::CREATED);
        }
        assert_eq!(app.post("/v1/auth/login", "10.0.1.4", json!({})).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn register_domain_mismatch_creates_no_user() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        let token = acme_token(&pool).await;
        let email = fresh_email("gmail.com");
        let (status, value) = app.register("10.0.1.5", &email, Some((token.id, &token.secret))).await;
        assert_eq!((status, value), (StatusCode::FORBIDDEN, json!({ "error": "ENROLLMENT_DOMAIN_MISMATCH" })));
        assert!(!app.user_exists(&email).await);
    }

    #[tokio::test]
    async fn register_with_bad_token_counts_against_ip_limit() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        for _ in 0..5 {
            let (status, _) = app.register("10.0.1.6", &fresh_email("acme.com"), Some((Uuid::new_v4(), "nope"))).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        assert_eq!(app.register("10.0.1.6", &fresh_email("acme.com"), None).await.0, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn register_ignores_the_token_when_team_invites_are_off() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features { team_invites: false, registration: false, ..Features::open() }, 5);
        let token = acme_token(&pool).await;
        let (status, value) = app.register("10.0.1.7", &fresh_email("acme.com"), Some((token.id, &token.secret))).await;
        assert_eq!((status, value), (StatusCode::FORBIDDEN, json!({ "error": "REGISTRATION_DISABLED" })));
    }

    #[tokio::test]
    async fn malformed_body_hits_the_registration_gate_first() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features { registration: false, ..Features::open() }, 5);
        assert_eq!(app.register_raw("10.0.1.8", "{not json").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn malformed_body_is_charged_to_the_ip_buckets() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 2);
        for _ in 0..2 {
            assert!(app.register_raw("10.0.1.9", "{not json").await.is_client_error());
        }
        assert_eq!(app.register_raw("10.0.1.9", "{not json").await, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn token_budget_is_keyed_on_the_token() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app_with_token_budget(&pool, Features::open(), 5, 2);
        let a = acme_token(&pool).await;
        let b = acme_token(&pool).await;
        for _ in 0..2 {
            assert_eq!(app.register("10.0.2.1", &fresh_email("acme.com"), Some((a.id, &a.secret))).await.0, StatusCode::CREATED);
        }
        let blocked = fresh_email("acme.com");
        assert_eq!(app.register("10.0.2.1", &blocked, Some((a.id, &a.secret))).await.0, StatusCode::TOO_MANY_REQUESTS);
        assert!(!app.user_exists(&blocked).await);
        assert_eq!(app.register("10.0.2.1", &fresh_email("acme.com"), Some((b.id, &b.secret))).await.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn dead_token_on_a_closed_server_creates_no_user_and_is_charged_to_the_ip() {
        let _billing = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features { registration: false, ..Features::open() }, 2);
        let (team, owner, manager) = business_team(&pool).await;
        let revoked = created(&pool, team, manager, body("member", &[], true)).await;
        revoke(&pool, team, manager).await.unwrap();
        let lapsed = created(&pool, team, manager, body("member", &[], true)).await;
        set_user_tier(&pool, owner, "free").await;

        let gone = fresh_email("acme.com");
        let (status, _) = app.register("10.0.2.2", &gone, Some((revoked.id, &revoked.secret))).await;
        assert_eq!(status, StatusCode::GONE);
        let unavailable = fresh_email("acme.com");
        let (status, value) = app.register("10.0.2.2", &unavailable, Some((lapsed.id, &lapsed.secret))).await;
        assert_eq!((status, value), (StatusCode::PAYMENT_REQUIRED, json!({ "error": "ENROLLMENT_UNAVAILABLE" })));
        assert!(!app.user_exists(&gone).await && !app.user_exists(&unavailable).await);
        let (status, _) = app.register("10.0.2.2", &fresh_email("acme.com"), Some((revoked.id, &revoked.secret))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    fn redeem_budget() -> EnrollmentRedeemRateLimiter {
        EnrollmentRedeemRateLimiter(RateLimiter::new(100, Duration::from_secs(3600)))
    }

    async fn insert_token(pool: &PgPool, team: Uuid, creator: Uuid, role: &str, domains: &[&str], approval: bool) -> (Uuid, String) {
        let secret = mint_secret();
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO team_enrollment_tokens (team_id, secret_hash, role, allowed_domains, require_approval, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(team)
        .bind(hash_secret(&secret))
        .bind(role)
        .bind(domains.iter().map(|d| d.to_string()).collect::<Vec<_>>())
        .bind(approval)
        .bind(creator)
        .fetch_one(pool)
        .await
        .unwrap();
        (id, secret)
    }

    async fn user_at(pool: &PgPool, email: &str, proven: bool) -> Uuid {
        let user = seed_user(pool).await;
        sqlx::query("UPDATE users SET email = $1, email_proven_at = CASE WHEN $2 THEN now() END WHERE id = $3")
            .bind(email)
            .bind(proven)
            .bind(user)
            .execute(pool)
            .await
            .unwrap();
        user
    }

    async fn redeem_as(pool: &PgPool, notifier: &SyncNotifier, user: Uuid, id: Uuid, secret: &str) -> Result<serde_json::Value, ApiError> {
        redeem_with_key(pool, notifier, user, id, secret, None).await
    }

    async fn redeem_with_key(
        pool: &PgPool,
        notifier: &SyncNotifier,
        user: Uuid,
        id: Uuid,
        secret: &str,
        public_key: Option<&str>,
    ) -> Result<serde_json::Value, ApiError> {
        let Json(outcome) = redeem(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier.clone()),
            Extension(redeem_budget()),
            Json(RedeemRequest { id, secret: secret.to_string(), public_key: public_key.map(str::to_string) }),
        )
        .await?;
        Ok(serde_json::to_value(outcome).unwrap())
    }

    async fn approve_as(pool: &PgPool, notifier: &SyncNotifier, actor: Uuid, team: Uuid, request: Uuid) -> Result<serde_json::Value, ApiError> {
        let Json(outcome) =
            approve(State(pool.clone()), Extension(AuthUser(actor)), Extension(notifier.clone()), Path((team, request))).await?;
        Ok(serde_json::to_value(outcome).unwrap())
    }

    async fn deny_as(pool: &PgPool, notifier: &SyncNotifier, actor: Uuid, team: Uuid, request: Uuid) -> Result<StatusCode, ApiError> {
        deny(State(pool.clone()), Extension(AuthUser(actor)), Extension(notifier.clone()), Path((team, request))).await
    }

    async fn pending_request(pool: &PgPool, team: Uuid, user: Uuid) -> (Uuid, Option<String>) {
        sqlx::query_as("SELECT id, reason FROM team_join_requests WHERE team_id = $1 AND user_id = $2 AND status = 'pending'")
            .bind(team)
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn assert_pending_reasons_set(pool: &PgPool, team: Uuid) {
        let unset: i64 = sqlx::query_scalar("SELECT count(*) FROM team_join_requests WHERE team_id = $1 AND status = 'pending' AND reason IS NULL")
            .bind(team)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(unset, 0);
    }

    async fn with_delivery<T>(f: impl std::future::Future<Output = T>) -> T {
        let previous = std::env::var("RESEND_API_KEY").ok();
        std::env::set_var("RESEND_API_KEY", "test-key");
        let out = f.await;
        match previous {
            Some(v) => std::env::set_var("RESEND_API_KEY", v),
            None => std::env::remove_var("RESEND_API_KEY"),
        }
        out
    }

    async fn request_count(pool: &PgPool, team: Uuid, user: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM team_join_requests WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn membership_count(pool: &PgPool, team: Uuid, user: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn builtin_roles_of(pool: &PgPool, team: Uuid, user: Uuid) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT tr.name FROM team_member_roles mr JOIN team_roles tr ON tr.id = mr.role_id WHERE mr.team_id = $1 AND mr.user_id = $2",
        )
        .bind(team)
        .bind(user)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn redeem_domain_only_proven_email_admits_and_uses_a_seat() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        let used_before = crate::routes::teams::owner_seats_used(&pool, owner).await.unwrap();

        let outcome = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();

        assert_eq!(outcome, json!({ "status": "admitted" }));
        assert_eq!(membership_count(&pool, team, user).await, 1);
        assert_eq!(builtin_roles_of(&pool, team, user).await, vec!["member".to_string()]);
        assert_eq!(crate::routes::teams::owner_seats_used(&pool, owner).await.unwrap(), used_before + 1);
        let invited_by: Option<Uuid> = sqlx::query_scalar("SELECT invited_by FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(invited_by, Some(manager));
        let (status, reason): (String, Option<String>) =
            sqlx::query_as("SELECT status, reason FROM team_join_requests WHERE team_id = $1 AND user_id = $2")
                .bind(team)
                .bind(user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((status.as_str(), reason), ("approved", None));
        assert_eq!(team_audit_count(&pool, team, "join_request.created").await, 1);
        assert_eq!(team_audit_count(&pool, team, "member.admitted").await, 1);
        let via: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM audit_logs WHERE team_id = $1 AND action = 'member.admitted'")
                .bind(team)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(via, json!({ "via": "enrollment" }));
        let last_used: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT last_used_at FROM team_enrollment_tokens WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(last_used.is_some());
    }

    #[tokio::test]
    async fn redeem_unproven_email_is_pending_then_verify_email_admits() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), false).await;

        let outcome = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        assert_eq!(outcome, json!({ "status": "pending", "reason": "email_unverified" }));
        assert_eq!(membership_count(&pool, team, user).await, 0);

        let token: String = sqlx::query_scalar("INSERT INTO email_verification_tokens (user_id) VALUES ($1) RETURNING token")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
        let _ = crate::routes::auth::verify_email(
            State(pool.clone()),
            Extension(Features::open()),
            Extension(notifier.clone()),
            Json(crate::routes::auth::VerifyEmailRequest { token }),
        )
        .await
        .unwrap();

        assert_eq!(membership_count(&pool, team, user).await, 1);
        let status: String = sqlx::query_scalar("SELECT status FROM team_join_requests WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "approved");
    }

    #[tokio::test]
    async fn redeem_with_approval_is_pending_until_approve() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("anywhere.org"), true).await;

        let outcome = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        assert_eq!(outcome, json!({ "status": "pending", "reason": "approval" }));
        assert_eq!(membership_count(&pool, team, user).await, 0);

        let Json(listed) = list_requests(
            State(pool.clone()),
            Extension(AuthUser(manager)),
            Path(team),
            Query(ListRequestsQuery { status: Some("pending".to_string()) }),
        )
        .await
        .unwrap();
        let listed = serde_json::to_value(listed).unwrap();
        let (request, _) = pending_request(&pool, team, user).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], request.to_string());
        assert_eq!(listed[0]["user_id"], user.to_string());
        assert_eq!(listed[0]["reason"], "approval");
        assert_eq!(listed[0]["email_proven"], true);
        assert!(listed[0]["email"].is_string() && listed[0]["display_name"].is_string() && listed[0]["created_at"].is_string());

        let (other_team, _, other_manager) = team_with_manager(&pool).await;
        assert_eq!(approve_as(&pool, &notifier, other_manager, other_team, request).await.unwrap_err().0, StatusCode::NOT_FOUND);
        assert_eq!(deny_as(&pool, &notifier, other_manager, other_team, request).await.unwrap_err().0, StatusCode::NOT_FOUND);

        assert_eq!(approve_as(&pool, &notifier, manager, team, request).await.unwrap(), json!({ "status": "admitted" }));
        assert_eq!(membership_count(&pool, team, user).await, 1);
        assert_eq!(team_audit_count(&pool, team, "join_request.approved").await, 1);
        assert_eq!(approve_as(&pool, &notifier, manager, team, request).await.unwrap_err().0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn approve_without_seat_is_402_and_stays_pending_seat_limit() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, owner, manager) = team_with_manager(&pool).await;
        crate::test_support::set_user_seats(&pool, owner, 1).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (request, _) = pending_request(&pool, team, user).await;

        let err = approve_as(&pool, &notifier, manager, team, request).await.unwrap_err();
        assert_eq!(error_code(err), (StatusCode::PAYMENT_REQUIRED, None));
        assert_eq!(pending_request(&pool, team, user).await, (request, Some("seat_limit".to_string())));
        assert_eq!(membership_count(&pool, team, user).await, 0);

        crate::test_support::set_user_seats(&pool, owner, 5).await;
        assert_eq!(approve_as(&pool, &notifier, manager, team, request).await.unwrap(), json!({ "status": "admitted" }));
    }

    #[tokio::test]
    async fn redeem_without_seat_reports_pending_seat_limit() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, owner, manager) = team_with_manager(&pool).await;
        crate::test_support::set_user_seats(&pool, owner, 1).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;

        let outcome = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        assert_eq!(outcome, json!({ "status": "pending", "reason": "seat_limit" }));
        assert_eq!(pending_request(&pool, team, user).await.1, Some("seat_limit".to_string()));
    }

    #[tokio::test]
    async fn redeem_twice_keeps_one_pending_row() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;

        for _ in 0..2 {
            let outcome = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
            assert_eq!(outcome, json!({ "status": "pending", "reason": "approval" }));
        }
        assert_eq!(request_count(&pool, team, user).await, 1);
        assert_eq!(team_audit_count(&pool, team, "join_request.created").await, 1);
        assert_pending_reasons_set(&pool, team).await;
    }

    #[tokio::test]
    async fn existing_member_gets_member() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], true).await;
        let user = user_at(&pool, &fresh_email("gmail.com"), true).await;
        add_member(&pool, team, user).await;

        assert_eq!(redeem_as(&pool, &notifier, user, id, &secret).await.unwrap(), json!({ "status": "member" }));
        assert_eq!(request_count(&pool, team, user).await, 0);
    }

    #[tokio::test]
    async fn domain_mismatch_creates_no_request() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], true).await;
        let user = user_at(&pool, &fresh_email("gmail.com"), true).await;

        let err = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap_err();
        assert_eq!(error_code(err), (StatusCode::FORBIDDEN, Some("ENROLLMENT_DOMAIN_MISMATCH")));
        assert_eq!(request_count(&pool, team, user).await, 0);
    }

    #[tokio::test]
    async fn deny_then_redeem_again_creates_a_new_pending_request() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (first, _) = pending_request(&pool, team, user).await;

        assert_eq!(deny_as(&pool, &notifier, manager, team, first).await.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(team_audit_count(&pool, team, "join_request.denied").await, 1);
        assert_eq!(deny_as(&pool, &notifier, manager, team, first).await.unwrap_err().0, StatusCode::NOT_FOUND);

        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (second, _) = pending_request(&pool, team, user).await;
        assert_ne!(first, second);
        assert_eq!(request_count(&pool, team, user).await, 2);
        assert_eq!(membership_count(&pool, team, user).await, 0);
    }

    #[tokio::test]
    async fn lapsed_team_redeem_402_approve_402_deny_204() {
        let _billing = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, owner, manager) = business_team(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let waiting = user_at(&pool, &fresh_email("acme.com"), true).await;
        redeem_as(&pool, &notifier, waiting, id, &secret).await.unwrap();
        let (request, _) = pending_request(&pool, team, waiting).await;

        set_user_tier(&pool, owner, "free").await;
        let newcomer = user_at(&pool, &fresh_email("acme.com"), true).await;
        let unavailable = (StatusCode::PAYMENT_REQUIRED, Some("ENROLLMENT_UNAVAILABLE"));
        assert_eq!(error_code(redeem_as(&pool, &notifier, newcomer, id, &secret).await.unwrap_err()), unavailable);
        assert_eq!(error_code(approve_as(&pool, &notifier, manager, team, request).await.unwrap_err()), unavailable);
        assert_eq!(request_count(&pool, team, newcomer).await, 0);
        assert_pending_reasons_set(&pool, team).await;
        assert_eq!(deny_as(&pool, &notifier, manager, team, request).await.unwrap(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rotated_token_requests_still_decidable() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let old = created(&pool, team, manager, body("editor", &[], true)).await;
        let a = user_at(&pool, &fresh_email("acme.com"), true).await;
        let b = user_at(&pool, &fresh_email("acme.com"), true).await;
        let c = user_at(&pool, &fresh_email("acme.com"), true).await;
        for user in [a, b, c] {
            redeem_as(&pool, &notifier, user, old.id, &old.secret).await.unwrap();
        }

        created(&pool, team, manager, body("member", &[], true)).await;
        assert_eq!(
            error_code(redeem_as(&pool, &notifier, seed_user(&pool).await, old.id, &old.secret).await.unwrap_err()),
            (StatusCode::GONE, None)
        );
        let (request_a, _) = pending_request(&pool, team, a).await;
        assert_eq!(approve_as(&pool, &notifier, manager, team, request_a).await.unwrap(), json!({ "status": "admitted" }));
        assert_eq!(builtin_roles_of(&pool, team, a).await, vec!["editor".to_string()]);

        let (request_b, _) = pending_request(&pool, team, b).await;
        assert_eq!(deny_as(&pool, &notifier, manager, team, request_b).await.unwrap(), StatusCode::NO_CONTENT);

        sqlx::query("DELETE FROM team_enrollment_tokens WHERE id = $1").bind(old.id).execute(&pool).await.unwrap();
        let (request_c, _) = pending_request(&pool, team, c).await;
        assert_eq!(approve_as(&pool, &notifier, manager, team, request_c).await.unwrap(), json!({ "status": "admitted" }));
        assert_eq!(builtin_roles_of(&pool, team, c).await, vec!["member".to_string()]);
    }

    #[tokio::test]
    async fn join_requests_event_reaches_only_invite_permission_holders() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let plain = member_with_role(&pool, team, PERM_CONNECT).await;
        let inviter = member_with_role(&pool, team, PERM_INVITE_MEMBERS).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        let mut rx = notifier.subscribe();

        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();

        let want = format!("join_requests:{team}");
        let mut told = std::collections::HashSet::new();
        while let Ok(event) = rx.try_recv() {
            if let SyncEvent::BlobPushed { user_id, device_id } = event {
                if device_id == want {
                    told.insert(user_id);
                }
            }
        }
        assert!(told.contains(&manager) && told.contains(&inviter));
        assert!(!told.contains(&plain) && !told.contains(&user));
    }

    #[tokio::test]
    async fn admission_sends_membership_changed() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        let mut rx = notifier.subscribe();

        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();

        let mut added = false;
        let mut roster_told = std::collections::HashSet::new();
        while let Ok(event) = rx.try_recv() {
            match event {
                SyncEvent::MembershipChanged { user_id, team_id, added: true } if user_id == user && team_id == team => added = true,
                SyncEvent::BlobPushed { user_id, device_id } if device_id == format!("team_members:{team}") => {
                    roster_told.insert(user_id);
                }
                _ => {}
            }
        }
        assert!(added);
        assert!(roster_told.contains(&manager) && roster_told.contains(&user));
    }

    #[tokio::test]
    async fn approve_and_verify_racing_admit_once() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), false).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (request, _) = pending_request(&pool, team, user).await;
        sqlx::query("UPDATE users SET email_proven_at = now() WHERE id = $1").bind(user).execute(&pool).await.unwrap();

        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM team_join_requests WHERE id = $1 FOR UPDATE").bind(request).fetch_one(&mut *gate).await.unwrap();
        let racers = [Some(manager), None].map(|by| {
            let (pool, notifier) = (pool.clone(), notifier.clone());
            tokio::spawn(async move { try_admit(&pool, &notifier, request, by).await })
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        gate.commit().await.unwrap();
        let [by_admin, by_verify] = racers;
        let (by_admin, by_verify) = (by_admin.await.unwrap(), by_verify.await.unwrap());

        assert_eq!([by_admin.is_ok(), by_verify.is_ok()].iter().filter(|ok| **ok).count(), 1);
        assert_eq!(membership_count(&pool, team, user).await, 1);
        let approved: i64 = sqlx::query_scalar("SELECT count(*) FROM team_join_requests WHERE id = $1 AND status = 'approved'")
            .bind(request)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(approved, 1);
        assert_eq!(team_audit_count(&pool, team, "member.admitted").await, 1);
    }

    #[tokio::test]
    async fn a_dead_token_never_auto_admits_a_verified_request() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), false).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (request, _) = pending_request(&pool, team, user).await;
        sqlx::query("UPDATE team_enrollment_tokens SET revoked_at = now() WHERE id = $1").bind(id).execute(&pool).await.unwrap();
        sqlx::query("UPDATE users SET email_proven_at = now() WHERE id = $1").bind(user).execute(&pool).await.unwrap();

        let outcome = try_admit(&pool, &notifier, request, None).await.unwrap();
        assert_eq!(outcome, RedeemOutcome::Pending(PendingReason::Approval));
        assert_eq!(membership_count(&pool, team, user).await, 0);
    }

    #[tokio::test]
    async fn register_with_token_redeems_in_the_same_call() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let app = signup_app(&pool, Features::open(), 5);
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let token = created(&pool, team, manager, body("member", &["acme.com"], true)).await;
        let email = fresh_email("acme.com");

        let (status, value) = app.register("10.0.3.1", &email, Some((token.id, &token.secret))).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(value["enrollment"], json!({ "status": "pending", "reason": "approval" }));
        assert!(value["jwt_token"].is_string());
        let user: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1").bind(&email).fetch_one(&pool).await.unwrap();
        assert_eq!(pending_request(&pool, team, user).await.1, Some("approval".to_string()));

        let (_, plain) = app.register("10.0.3.1", &fresh_email("acme.com"), None).await;
        assert!(plain.get("enrollment").is_none());
    }

    #[tokio::test]
    async fn redeem_without_public_key_is_400_and_creates_no_request() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        sqlx::query("UPDATE users SET public_key = NULL WHERE id = $1").bind(user).execute(&pool).await.unwrap();

        let err = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap_err();
        assert_eq!(error_code(err), (StatusCode::BAD_REQUEST, None));
        assert_eq!(request_count(&pool, team, user).await, 0);

        let outcome = redeem_with_key(&pool, &notifier, user, id, &secret, Some("fresh-key")).await.unwrap();
        assert_eq!(outcome, json!({ "status": "pending", "reason": "approval" }));
    }

    #[tokio::test]
    async fn both_guard_token_with_unproven_email_waits_for_verification_not_approval() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), false).await;

        let (redeemed, approved) = with_delivery(async {
            let redeemed = redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
            let (request, _) = pending_request(&pool, team, user).await;
            (redeemed, approve_as(&pool, &notifier, manager, team, request).await.unwrap())
        })
        .await;

        let pending = json!({ "status": "pending", "reason": "email_unverified" });
        assert_eq!((redeemed, approved), (pending.clone(), pending));
        assert_eq!(membership_count(&pool, team, user).await, 0);
        assert_eq!(pending_request(&pool, team, user).await.1, Some("email_unverified".to_string()));
    }

    #[tokio::test]
    async fn domain_only_unproven_approve_stays_pending() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &["acme.com"], false).await;
        let user = user_at(&pool, &fresh_email("acme.com"), false).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (request, _) = pending_request(&pool, team, user).await;

        let approved = with_delivery(async { approve_as(&pool, &notifier, manager, team, request).await.unwrap() }).await;

        assert_eq!(approved, json!({ "status": "pending", "reason": "email_unverified" }));
        assert_eq!(membership_count(&pool, team, user).await, 0);
    }

    #[tokio::test]
    async fn approval_only_token_with_unproven_email_is_admitted_on_approve() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), false).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (request, reason) = pending_request(&pool, team, user).await;
        assert_eq!(reason, Some("approval".to_string()));

        let approved = with_delivery(async { approve_as(&pool, &notifier, manager, team, request).await.unwrap() }).await;

        assert_eq!(approved, json!({ "status": "admitted" }));
        assert_eq!(membership_count(&pool, team, user).await, 1);
    }

    #[tokio::test]
    async fn already_member_decision_notifies_join_request_holders() {
        let _billing = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let notifier = SyncNotifier::new();
        let (team, _owner, manager) = team_with_manager(&pool).await;
        let (id, secret) = insert_token(&pool, team, manager, "member", &[], true).await;
        let user = user_at(&pool, &fresh_email("acme.com"), true).await;
        redeem_as(&pool, &notifier, user, id, &secret).await.unwrap();
        let (request, _) = pending_request(&pool, team, user).await;
        add_member(&pool, team, user).await;
        let mut rx = notifier.subscribe();

        assert_eq!(try_admit(&pool, &notifier, request, Some(manager)).await.unwrap(), RedeemOutcome::Member);

        let want = format!("join_requests:{team}");
        let mut told = false;
        while let Ok(event) = rx.try_recv() {
            told |= matches!(event, SyncEvent::BlobPushed { user_id, device_id } if user_id == manager && device_id == want);
        }
        assert!(told);
    }
}
