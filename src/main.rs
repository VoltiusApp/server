mod auth;
mod db;
mod email;
mod models;
mod permissions;
mod rate_limit;
mod routes;
mod sync_notifier;
mod terminal_manager;

use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Extension, Router,
};
use dashmap::{DashMap, DashSet};
use rate_limit::{InviteRateLimiter, RateLimiter, RegisterRateLimiter, SyncRateLimiter};
use routes::audit::AuditClientRateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use sync_notifier::SyncNotifier;
use terminal_manager::TerminalManager;
use uuid::Uuid;

pub type PresenceMap = Arc<DashMap<Uuid, ()>>;
/// Per-user set of connection IDs the user is currently broadcasting as "in use".
/// Connection IDs are stored as strings to match team_vault_objects.object_id (TEXT).
pub type UsageMap = Arc<DashMap<Uuid, DashSet<String>>>;
use axum::http::{header, HeaderValue};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let pool = db::create_pool().await;

    // Audit log retention: delete entries older than each team's retention window (runs every 24h)
    let retention_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(86_400));
        interval.tick().await; // skip first immediate tick
        loop {
            interval.tick().await;
            match sqlx::query(
                r#"DELETE FROM audit_logs
                   USING teams
                   WHERE audit_logs.team_id = teams.id
                     AND audit_logs.created_at < NOW() - (teams.audit_retention_days * INTERVAL '1 day')"#,
            )
            .execute(&retention_pool)
            .await
            {
                Ok(r) => tracing::info!(deleted = r.rows_affected(), "Audit log retention cleanup completed"),
                Err(e) => tracing::error!(error = %e, "Audit log retention cleanup failed"),
            }
        }
    });

    let notifier = SyncNotifier::new();
    let terminal_manager = TerminalManager::new();
    let presence_map: PresenceMap = Arc::new(DashMap::new());
    let usage_map: UsageMap = Arc::new(DashMap::new());

    // Rate limiters (configurable via env for dev)
    let sync_rate: usize = std::env::var("SYNC_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let register_per_day: usize = std::env::var("REGISTER_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let invite_per_hour: usize = std::env::var("INVITE_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let auth_limiter = RateLimiter::<std::net::IpAddr>::new(10, Duration::from_secs(60));
    let register_limiter = RegisterRateLimiter(RateLimiter::new(
        register_per_day,
        Duration::from_secs(86400),
    ));
    let invite_limiter = InviteRateLimiter(RateLimiter::<uuid::Uuid>::new(
        invite_per_hour,
        Duration::from_secs(3600),
    ));
    let sync_limiter = SyncRateLimiter(RateLimiter::<uuid::Uuid>::new(
        sync_rate,
        Duration::from_secs(3600),
    ));
    let audit_client_limiter =
        AuditClientRateLimiter(RateLimiter::<uuid::Uuid>::new(100, Duration::from_secs(60)));
    tracing::info!(
        auth_per_minute = 10,
        register_per_day,
        invite_per_hour,
        sync_per_hour = sync_rate,
        "Configured rate limits"
    );

    // Register — stricter limit: 5/day per IP on top of the general auth 10/min
    let register_route = Router::new()
        .route("/v1/auth/register", post(routes::auth::register))
        .layer(middleware::from_fn(rate_limit::register_rate_limit))
        .layer(Extension(register_limiter))
        .layer(middleware::from_fn(rate_limit::auth_rate_limit))
        .layer(Extension(auth_limiter.clone()));

    // Public auth + public invitation lookup — rate limited at 10/min per IP
    let public = Router::new()
        .route("/v1/auth/challenge", get(routes::auth::challenge))
        .route("/v1/auth/login", post(routes::auth::login))
        .route("/v1/auth/refresh", post(routes::auth::refresh))
        .route("/v1/auth/verify-email", post(routes::auth::verify_email))
        .route(
            "/v1/invitations/:token",
            get(routes::invitations::get_invitation),
        )
        .layer(middleware::from_fn(rate_limit::auth_rate_limit))
        .layer(Extension(auth_limiter));

    // Webhook — public, signature-verified internally
    let webhooks = Router::new()
        .route(
            "/v1/webhooks/lemonsqueezy",
            post(routes::webhooks::lemonsqueezy_webhook),
        )
        .layer(Extension(notifier.clone()));

    // Invite — auth required + dedicated 20/hr limit (sends email)
    let invite_route = Router::new()
        .route(
            "/v1/teams/:team_id/invite",
            post(routes::teams::invite_member),
        )
        .layer(middleware::from_fn(rate_limit::invite_rate_limit))
        .layer(Extension(invite_limiter))
        .layer(middleware::from_fn(auth::auth_middleware))
        .layer(Extension(notifier.clone()));

    // Pro-gated sync routes (auth → rate limit → tier check)
    let pro_sync = Router::new()
        .route("/v1/sync/blob", get(routes::sync::get_blob))
        .route("/v1/sync/blob", put(routes::sync::put_blob))
        .layer(middleware::from_fn(auth::require_pro))
        .layer(middleware::from_fn(rate_limit::sync_rate_limit))
        .layer(Extension(sync_limiter.clone()))
        .layer(middleware::from_fn(auth::auth_middleware))
        .layer(Extension(notifier.clone()))
        .layer(Extension(presence_map.clone()));

    // Teams-gated router — creating a team vault requires Teams or Business tier
    let teams_gated = Router::new()
        .route("/v1/teams", post(routes::teams::create_team))
        .layer(middleware::from_fn(auth::require_teams))
        .layer(middleware::from_fn(auth::auth_middleware))
        .layer(Extension(notifier.clone()))
        .layer(Extension(presence_map.clone()));

    // Audit log — client self-reporting (CONNECT permission + rate limit by team_id)
    let audit_client = Router::new()
        .route(
            "/v1/teams/:team_id/audit-logs/client",
            axum::routing::post(routes::audit::report_client_event),
        )
        .layer(Extension(audit_client_limiter))
        .layer(middleware::from_fn(auth::auth_middleware));

    // Protected routes — auth required + rate limited at 60/hour per IP
    let protected = Router::new()
        .route("/v1/auth/account", delete(routes::auth::delete_account))
        .route("/v1/auth/me", get(routes::auth::get_me))
        .route("/v1/auth/display-name", put(routes::auth::update_display_name))
        .route("/v1/auth/email", put(routes::auth::update_email))
        .route("/v1/auth/password", put(routes::auth::update_password))
        .route(
            "/v1/auth/wrapped-user-secrets",
            put(routes::auth::upload_wrapped_user_secrets),
        )
        .route(
            "/v1/auth/resend-verification-email",
            post(routes::auth::resend_verification_email),
        )
        .route("/v1/auth/public-key", put(routes::teams::update_public_key))
        .route("/v1/sync/devices", get(routes::sync::list_devices))
        .route("/v1/sync/stream", get(routes::sync::sync_stream))
        .route(
            "/v1/presence/connection-usage",
            get(routes::presence::get_connection_usage),
        )
        .route(
            "/v1/presence/connection-usage",
            post(routes::presence::post_connection_usage),
        )
        .route(
            "/v1/sync/blob/:device_id",
            delete(routes::sync::delete_blob),
        )
        // Teams — read routes open to all authed users
        .route("/v1/teams", get(routes::teams::list_teams))
        .route(
            "/v1/teams/:team_id/members",
            get(routes::teams::list_members),
        )
        .route(
            "/v1/teams/:team_id/members",
            post(routes::teams::add_member),
        )
        .route("/v1/teams/:team_id", delete(routes::teams::delete_team))
        .route(
            "/v1/teams/:team_id/members/:user_id",
            delete(routes::teams::remove_member),
        )
        .route(
            "/v1/teams/:team_id/members/:user_id/roles",
            get(routes::teams::list_member_roles),
        )
        .route(
            "/v1/teams/:team_id/members/:user_id/roles",
            post(routes::teams::assign_member_role),
        )
        .route(
            "/v1/teams/:team_id/members/:user_id/roles/:role_id",
            delete(routes::teams::remove_member_role),
        )
        .route("/v1/users/search", get(routes::teams::search_users))
        // Team invitations (invite POST is on invite_route with stricter rate limit)
        .route(
            "/v1/teams/:team_id/pending-invitations",
            get(routes::teams::list_pending_invitations),
        )
        .route(
            "/v1/teams/:team_id/pending-invitations/:inv_id",
            delete(routes::teams::revoke_pending_invitation),
        )
        .route(
            "/v1/invitations/:token/accept",
            post(routes::invitations::accept_invitation),
        )
        // In-app pending invitation consent flow
        .route(
            "/v1/my/pending-invitations",
            get(routes::invitations::list_my_pending_invitations),
        )
        .route(
            "/v1/my/pending-invitations/:inv_id/accept",
            post(routes::invitations::accept_my_pending_invitation),
        )
        .route(
            "/v1/my/pending-invitations/:inv_id",
            delete(routes::invitations::decline_my_pending_invitation),
        )
        // Custom roles
        .route("/v1/teams/:team_id/roles", get(routes::teams::list_roles))
        .route("/v1/teams/:team_id/roles", post(routes::teams::create_role))
        .route(
            "/v1/teams/:team_id/roles/:role_id",
            patch(routes::teams::update_role),
        )
        .route(
            "/v1/teams/:team_id/roles/:role_id",
            delete(routes::teams::delete_role),
        )
        // Team vault sync
        .route(
            "/v1/teams/:team_id/vault-key",
            get(routes::team_sync::get_my_vault_key),
        )
        .route(
            "/v1/teams/:team_id/vault-key",
            put(routes::team_sync::put_vault_keys),
        )
        .route(
            "/v1/teams/:team_id/sync-blob",
            get(routes::team_sync::get_team_blob),
        )
        .route(
            "/v1/teams/:team_id/sync-blob",
            put(routes::team_sync::put_team_blob),
        )
        .route(
            "/v1/teams/:team_id/objects",
            get(routes::team_objects::list_objects),
        )
        .route(
            "/v1/teams/:team_id/objects",
            put(routes::team_objects::upsert_object),
        )
        .route(
            "/v1/teams/:team_id/objects/:object_id",
            delete(routes::team_objects::delete_object),
        )
        .route(
            "/v1/teams/:team_id/object_prefs",
            get(routes::team_object_prefs::list_object_prefs),
        )
        .route(
            "/v1/teams/:team_id/object_prefs/:object_id",
            put(routes::team_object_prefs::upsert_object_pref),
        )
        .route(
            "/v1/teams/:team_id/object_prefs/:object_id",
            delete(routes::team_object_prefs::delete_object_pref),
        )
        .route(
            "/v1/teams/:team_id/secrets",
            get(routes::team_objects::list_secrets),
        )
        .route(
            "/v1/teams/:team_id/secrets",
            put(routes::team_objects::upsert_secret),
        )
        // Terminal sessions (REST) — Pro-gated at handler level via claims
        .route(
            "/v1/terminal-sessions",
            get(routes::terminal::list_active_sessions),
        )
        .route(
            "/v1/terminal-sessions",
            post(routes::terminal::create_session),
        )
        .route(
            "/v1/terminal-sessions/:id/my-key",
            get(routes::terminal::get_my_session_key),
        )
        .route(
            "/v1/terminal-sessions/:id",
            delete(routes::terminal::end_session),
        )
        // Audit logs — read + export (VIEW_AUDIT_LOG enforced in handler)
        .route(
            "/v1/teams/:team_id/audit-logs",
            get(routes::audit::list_audit_logs),
        )
        .route(
            "/v1/teams/:team_id/audit-logs/export",
            get(routes::audit::export_audit_logs),
        )
        // Billing
        .route(
            "/v1/billing/checkout",
            post(routes::billing::create_checkout),
        )
        .route("/v1/billing/portal", post(routes::billing::get_portal))
        .route("/v1/billing/seats", post(routes::billing::update_seats))
        .route(
            "/v1/billing/subscription",
            get(routes::billing::get_subscription),
        )
        .route(
            "/v1/billing/subscription/cancel",
            post(routes::billing::cancel_subscription),
        )
        .route(
            "/v1/billing/subscription/resume",
            post(routes::billing::resume_subscription),
        )
        .layer(middleware::from_fn(rate_limit::sync_rate_limit))
        .layer(Extension(sync_limiter))
        .layer(middleware::from_fn(auth::auth_middleware))
        .layer(Extension(notifier.clone()))
        .layer(Extension(terminal_manager.clone()))
        .layer(Extension(presence_map.clone()))
        .layer(Extension(usage_map.clone()));

    // Admin routes — auth + admin check, no rate limit (internal tool)
    let admin_routes = Router::new()
        .route("/v1/admin/stats", get(routes::admin::get_stats))
        .route(
            "/v1/admin/users/export",
            get(routes::admin::export_users_csv),
        )
        .route("/v1/admin/users", get(routes::admin::list_users))
        .route("/v1/admin/users/:id", get(routes::admin::get_user))
        .route("/v1/admin/users/:id", patch(routes::admin::patch_user))
        .route("/v1/admin/users/:id", delete(routes::admin::delete_user))
        .route(
            "/v1/admin/users/:id/restore",
            post(routes::admin::restore_user),
        )
        .route("/v1/admin/users/:id/ban", post(routes::admin::ban_user))
        .route("/v1/admin/users/:id/unban", post(routes::admin::unban_user))
        .route(
            "/v1/admin/users/:id/extend-trial",
            post(routes::admin::extend_trial),
        )
        .route(
            "/v1/admin/users/:id/devices",
            get(routes::admin::list_devices),
        )
        .route("/v1/admin/users/:id/flags", get(routes::admin::list_flags))
        .route(
            "/v1/admin/users/:id/flags/:flag",
            put(routes::admin::set_flag),
        )
        .route(
            "/v1/admin/users/:id/churn",
            get(routes::admin::list_user_churn),
        )
        .route("/v1/admin/audit-log", get(routes::admin::list_audit_log))
        .route("/v1/admin/churn", get(routes::admin::list_churn))
        .route("/v1/admin/presence", get(routes::admin::get_presence))
        .layer(middleware::from_fn(auth::require_admin_key))
        .layer(Extension(notifier.clone()))
        .layer(Extension(presence_map.clone()));

    // WebSocket terminal relay — auth via query param (not middleware)
    let ws_routes = Router::new()
        .route(
            "/v1/terminal-sessions/:id/ws",
            get(routes::terminal::ws_handler),
        )
        .layer(Extension(terminal_manager));

    let app = Router::new()
        .merge(public)
        .merge(register_route)
        .merge(webhooks)
        .merge(invite_route)
        .merge(pro_sync)
        .merge(teams_gated)
        .merge(audit_client)
        .merge(protected)
        .merge(admin_routes)
        .merge(ws_routes)
        .route("/health", get(|| async { "ok" }))
        .layer({
            let allow_origin = match std::env::var("CORS_ORIGINS") {
                Ok(s) => {
                    let origins: Vec<HeaderValue> =
                        s.split(',').filter_map(|o| o.trim().parse().ok()).collect();
                    if origins.is_empty() {
                        AllowOrigin::any()
                    } else {
                        AllowOrigin::list(origins)
                    }
                }
                Err(_) => AllowOrigin::any(),
            };
            CorsLayer::new()
                .allow_origin(allow_origin)
                .allow_methods(Any)
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        })
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
        )
        .with_state(pool);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{port}");
    tracing::info!("Starting server on {addr}");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, %addr, "Failed to bind TCP listener");
            return;
        }
    };

    if let Err(error) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        tracing::error!(%error, "Server exited with an error");
    }
}
