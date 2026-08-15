use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::Response,
    Extension, Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AdminEmail;
use crate::lemonsqueezy::{LsCache, LsSummaryResponse};
use crate::sync_notifier::SyncNotifier;
use crate::PresenceMap;

// ─── Audit helper ─────────────────────────────────────────────────────────────

async fn write_audit(
    pool: &PgPool,
    admin_email: &str,
    target_id: Option<Uuid>,
    action: &str,
    detail: Value,
) {
    let result = sqlx::query(
        "INSERT INTO admin_audit_log (admin_email, target_id, action, detail) VALUES ($1, $2, $3, $4)",
    )
    .bind(admin_email)
    .bind(target_id)
    .bind(action)
    .bind(detail)
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!(error = %e, admin_email = %admin_email, action = %action, "Failed to write audit log");
    }
}

// ─── Lemon Squeezy live summary ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LsSummaryQuery {
    /// If true, force a fresh fetch from LS before returning.
    refresh: Option<bool>,
}

pub async fn get_lemonsqueezy_summary(
    Extension(cache): Extension<LsCache>,
    Query(q): Query<LsSummaryQuery>,
) -> Json<LsSummaryResponse> {
    if q.refresh.unwrap_or(false) {
        let _ = cache.refresh().await;
    }
    Json(cache.summary().await)
}

// ─── Overview (home page) ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TierBreakdown {
    free: i64,
    pro: i64,
    pro_trial: i64,
    teams: i64,
    business: i64,
}

#[derive(Serialize)]
pub struct OverviewResponse {
    mrr_total: i64,
    mrr_by_tier: TierMrr,
    paying_subscribers: i64,
    trials_active: i64,
    trials_expiring_7d: i64,
    signups_7d: i64,
    signups_30d: i64,
    churn_7d: i64,
    churn_30d: i64,
    total_users: i64,
    deleted_pending: i64,
    total_blob_gb: f64,
    conversion_pct: f64,
    active_7d: i64,
    active_30d: i64,
    never_seen: i64,
    tier_breakdown: TierBreakdown,
    signups_series: Vec<DayBucket>,
    churn_series: Vec<DayBucket>,
    recent_signups: Vec<RecentUser>,
    recent_churn: Vec<RecentChurnRow>,
}

#[derive(Serialize)]
pub struct TierMrr {
    pro: i64,
    teams: i64,
    business: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DayBucket {
    day: chrono::NaiveDate,
    count: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RecentUser {
    id: Uuid,
    email: String,
    subscription_tier: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RecentChurnRow {
    id: Uuid,
    user_id: Uuid,
    from_tier: String,
    to_tier: String,
    reason: Option<String>,
    created_at: DateTime<Utc>,
}

// Monthly price per paying unit. teams/business are per-seat; pro is per-user.
const PRICE_PRO: i64 = 7;
const PRICE_TEAMS_PER_SEAT: i64 = 15;
const PRICE_BUSINESS_PER_SEAT: i64 = 49;

pub async fn get_overview(State(pool): State<PgPool>) -> Result<Json<OverviewResponse>, StatusCode> {
    // ── Headline counts ──────────────────────────────────────────────────────
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64, i64, Option<f64>)>(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE deleted_at IS NULL),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND subscription_tier = 'free'),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND subscription_tier = 'pro'),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND subscription_tier = 'teams'),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND subscription_tier = 'business'),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND trial_ends_at IS NOT NULL AND trial_ends_at > now()),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND trial_ends_at IS NOT NULL AND trial_ends_at > now() AND trial_ends_at < now() + interval '7 days'),
            COUNT(*) FILTER (WHERE deleted_at IS NOT NULL),
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND subscription_tier = 'pro' AND (trial_ends_at IS NULL OR trial_ends_at <= now())),
            NULL::float8
        FROM users
        "#,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: counts failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let total_users = row.0;
    let free_users = row.1;
    let pro_users = row.2;
    let teams_users = row.3;
    let business_users = row.4;
    let trials_active = row.5;
    let trials_expiring_7d = row.6;
    let deleted_pending = row.7;
    let paid_pro_users = row.8;

    // ── MRR (seat-aware for teams/business) ──────────────────────────────────
    let seat_row = sqlx::query_as::<_, (Option<i64>, Option<i64>)>(
        r#"
        SELECT
            SUM(COALESCE(seat_count, 3)) FILTER (WHERE subscription_tier = 'teams' AND deleted_at IS NULL),
            SUM(COALESCE(seat_count, 3)) FILTER (WHERE subscription_tier = 'business' AND deleted_at IS NULL)
        FROM users
        "#,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: seat sums failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let teams_seats = seat_row.0.unwrap_or(0);
    let business_seats = seat_row.1.unwrap_or(0);

    let mrr_pro = pro_users * PRICE_PRO;
    let mrr_teams = teams_seats * PRICE_TEAMS_PER_SEAT;
    let mrr_business = business_seats * PRICE_BUSINESS_PER_SEAT;
    let mrr_total = mrr_pro + mrr_teams + mrr_business;
    let paying_subscribers = paid_pro_users + teams_users + business_users;

    // ── Recent windows ───────────────────────────────────────────────────────
    let (signups_7d, signups_30d): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE created_at > now() - interval '7 days'),
            COUNT(*) FILTER (WHERE created_at > now() - interval '30 days')
        FROM users
        WHERE deleted_at IS NULL
        "#,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: signups windows failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (churn_7d, churn_30d): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE created_at > now() - interval '7 days'),
            COUNT(*) FILTER (WHERE created_at > now() - interval '30 days')
        FROM churn_events
        "#,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: churn windows failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // ── Storage ──────────────────────────────────────────────────────────────
    let blob_row = sqlx::query_as::<_, (Option<f64>,)>(
        "SELECT SUM(size_bytes)::float8 / 1073741824.0 FROM sync_blobs",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: blob size failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // ── Time series: signups & churn per day, last 90 days (gap-filled) ──────
    let signups_series = sqlx::query_as::<_, DayBucket>(
        r#"
        WITH days AS (
          SELECT generate_series(
            date_trunc('day', now() - interval '89 days'),
            date_trunc('day', now()),
            interval '1 day'
          )::date AS day
        )
        SELECT d.day, COALESCE(COUNT(u.id), 0)::bigint AS count
        FROM days d
        LEFT JOIN users u
          ON date_trunc('day', u.created_at)::date = d.day
          AND u.deleted_at IS NULL
        GROUP BY d.day
        ORDER BY d.day
        "#,
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: signups series failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let churn_series = sqlx::query_as::<_, DayBucket>(
        r#"
        WITH days AS (
          SELECT generate_series(
            date_trunc('day', now() - interval '89 days'),
            date_trunc('day', now()),
            interval '1 day'
          )::date AS day
        )
        SELECT d.day, COALESCE(COUNT(c.id), 0)::bigint AS count
        FROM days d
        LEFT JOIN churn_events c
          ON date_trunc('day', c.created_at)::date = d.day
        GROUP BY d.day
        ORDER BY d.day
        "#,
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: churn series failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // ── Recent lists ─────────────────────────────────────────────────────────
    let recent_signups = sqlx::query_as::<_, RecentUser>(
        "SELECT id, email, subscription_tier, created_at
         FROM users
         WHERE deleted_at IS NULL
         ORDER BY created_at DESC LIMIT 5",
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: recent signups failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let recent_churn = sqlx::query_as::<_, RecentChurnRow>(
        "SELECT id, user_id, from_tier, to_tier, reason, created_at
         FROM churn_events ORDER BY created_at DESC LIMIT 5",
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "overview: recent churn failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // ── Activity (coarse, from users.last_seen_on) ───────────────────────────
    let activity = crate::last_seen::activity_counts(&pool).await.map_err(|e| {
        error!(error = %e, "overview: activity counts failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let conversion_pct = if total_users > 0 {
        (paying_subscribers as f64 / total_users as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(OverviewResponse {
        mrr_total,
        mrr_by_tier: TierMrr {
            pro: mrr_pro,
            teams: mrr_teams,
            business: mrr_business,
        },
        paying_subscribers,
        trials_active,
        trials_expiring_7d,
        signups_7d,
        signups_30d,
        churn_7d,
        churn_30d,
        total_users,
        deleted_pending,
        total_blob_gb: blob_row.0.unwrap_or(0.0),
        conversion_pct,
        active_7d: activity.active_7d,
        active_30d: activity.active_30d,
        never_seen: activity.never_seen,
        tier_breakdown: TierBreakdown {
            free: free_users,
            pro: paid_pro_users,
            pro_trial: pro_users - paid_pro_users,
            teams: teams_users,
            business: business_users,
        },
        signups_series,
        churn_series,
        recent_signups,
        recent_churn,
    }))
}

// ─── Users list ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UsersQuery {
    page: Option<i64>,
    limit: Option<i64>,
    search: Option<String>,
    tier: Option<String>,
    banned: Option<bool>,
    /// "exclude" (default), "only", "any".
    deleted: Option<String>,
    /// Whitelisted sort column: "created_at" (default) or "last_seen_on".
    sort: Option<String>,
    /// "desc" (default) or "asc".
    dir: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserListRow {
    id: Uuid,
    email: String,
    subscription_tier: String,
    trial_ends_at: Option<DateTime<Utc>>,
    trial_used: bool,
    is_banned: bool,
    is_admin: bool,
    created_at: DateTime<Utc>,
    ls_customer_id: Option<String>,
    total_blob_bytes: Option<i64>,
    device_count: Option<i64>,
    last_churn_at: Option<DateTime<Utc>>,
    /// Coarse liveness date; NULL means the account has not been seen since
    /// `last_seen_on` shipped, which is not the same as dormant.
    last_seen_on: Option<chrono::NaiveDate>,
    deleted_at: Option<DateTime<Utc>>,
}

pub async fn list_users(
    State(pool): State<PgPool>,
    Query(params): Query<UsersQuery>,
) -> Result<Json<Value>, StatusCode> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = (page - 1) * limit;

    // deleted: "exclude" (default) / "only" / "any"
    let deleted_clause = match params.deleted.as_deref() {
        Some("only") => "AND u.deleted_at IS NOT NULL",
        Some("any") => "",
        _ => "AND u.deleted_at IS NULL",
    };

    // Sort column and direction are matched against a whitelist and never
    // interpolated from user input — the query is built with format!.
    let dir = match params.dir.as_deref() {
        None | Some("desc") => "DESC",
        Some("asc") => "ASC",
        Some(other) => {
            warn!(dir = %other, "Rejected unknown sort direction");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    // Every ordering ends in u.id: LIMIT/OFFSET paging over a non-unique key can
    // repeat or skip rows between pages when values tie, and last_seen_on ties
    // constantly (one date per day, plus every never-seen account sharing NULL).
    let order_clause = match params.sort.as_deref() {
        None | Some("created_at") => format!("u.created_at {dir}, u.id"),
        // NULLS LAST in both directions: a never-seen account is unknown, not
        // the oldest or the newest, and must not head either ordering.
        Some("last_seen_on") => {
            format!("u.last_seen_on {dir} NULLS LAST, u.created_at DESC, u.id")
        }
        Some(other) => {
            warn!(sort = %other, "Rejected unknown sort column");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let list_sql = format!(
        r#"
        SELECT
            u.id,
            u.email,
            u.subscription_tier,
            u.trial_ends_at,
            u.trial_used,
            u.is_banned,
            u.is_admin,
            u.created_at,
            u.ls_customer_id,
            COALESCE(sb.total_blob_bytes, 0)::bigint AS total_blob_bytes,
            COALESCE(sb.device_count, 0)::bigint AS device_count,
            ce.last_churn_at,
            u.last_seen_on,
            u.deleted_at
        FROM users u
        LEFT JOIN (
            SELECT user_id,
                   SUM(size_bytes)::bigint AS total_blob_bytes,
                   COUNT(DISTINCT device_id)::bigint AS device_count
            FROM sync_blobs
            GROUP BY user_id
        ) sb ON sb.user_id = u.id
        LEFT JOIN (
            SELECT user_id, MAX(created_at) AS last_churn_at
            FROM churn_events
            GROUP BY user_id
        ) ce ON ce.user_id = u.id
        WHERE
            ($1::text IS NULL OR u.email ILIKE '%' || $1 || '%')
            AND ($2::text IS NULL OR u.subscription_tier = $2)
            AND ($3::boolean IS NULL OR u.is_banned = $3)
            {deleted_clause}
        ORDER BY {order_clause}
        LIMIT $4 OFFSET $5
        "#
    );

    let rows = sqlx::query_as::<_, UserListRow>(&list_sql)
        .bind(&params.search)
        .bind(&params.tier)
        .bind(params.banned)
        .bind(limit)
        .bind(offset)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to list users");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let count_sql = format!(
        r#"
        SELECT COUNT(*) FROM users u
        WHERE
            ($1::text IS NULL OR u.email ILIKE '%' || $1 || '%')
            AND ($2::text IS NULL OR u.subscription_tier = $2)
            AND ($3::boolean IS NULL OR u.is_banned = $3)
            {deleted_clause}
        "#
    );

    let total_row = sqlx::query_as::<_, (i64,)>(&count_sql)
        .bind(&params.search)
        .bind(&params.tier)
        .bind(params.banned)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to count users");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({
        "users": rows,
        "total": total_row.0,
        "page": page,
        "limit": limit,
    })))
}

// ─── User detail ──────────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct UserDetail {
    id: Uuid,
    email: String,
    account_id: Uuid,
    subscription_tier: String,
    trial_ends_at: Option<DateTime<Utc>>,
    trial_used: bool,
    is_banned: bool,
    is_admin: bool,
    ban_reason: Option<String>,
    banned_at: Option<DateTime<Utc>>,
    admin_notes: Option<String>,
    discount_pct: Option<i16>,
    ls_customer_id: Option<String>,
    ls_subscription_id: Option<String>,
    admin_override: bool,
    created_at: DateTime<Utc>,
    seat_count: Option<i32>,
    /// See `UserListRow::last_seen_on`.
    last_seen_on: Option<chrono::NaiveDate>,
    deleted_at: Option<DateTime<Utc>>,
    deletion_reason: Option<String>,
    deleted_by: Option<String>,
}

pub async fn get_user(
    State(pool): State<PgPool>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserDetail>, StatusCode> {
    let user = sqlx::query_as::<_, UserDetail>(
        r#"
        SELECT id, email, account_id, subscription_tier, trial_ends_at, trial_used,
               is_banned, is_admin, ban_reason, banned_at, admin_notes, discount_pct,
               ls_customer_id, ls_subscription_id, admin_override, created_at, seat_count,
               last_seen_on, deleted_at, deletion_reason, deleted_by
        FROM users WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch user detail");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(user))
}

// ─── User patch ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PatchUserRequest {
    tier: Option<String>,
    trial_ends_at: Option<DateTime<Utc>>,
    clear_trial: Option<bool>,
    trial_used: Option<bool>,
    discount_pct: Option<i16>,
    admin_notes: Option<String>,
    admin_override: Option<bool>,
    seat_count: Option<i32>,
}

pub async fn patch_user(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<PatchUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let current = sqlx::query_as::<_, (String,)>(
        "SELECT subscription_tier FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch user for patch");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    let old_tier = current.0;

    if let Some(ref new_tier) = body.tier {
        let tier_order = |t: &str| match t {
            "business" => 3,
            "teams" => 2,
            "pro" => 1,
            _ => 0,
        };
        if tier_order(new_tier) < tier_order(&old_tier) {
            sqlx::query(
                "INSERT INTO churn_events (user_id, from_tier, to_tier, reason) VALUES ($1, $2, $3, 'admin')",
            )
            .bind(user_id)
            .bind(&old_tier)
            .bind(new_tier)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to record churn event");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        }
    }

    sqlx::query(
        r#"
        UPDATE users SET
            subscription_tier = COALESCE($1, subscription_tier),
            trial_ends_at = CASE
                WHEN $2 = TRUE THEN NULL
                WHEN $3::timestamptz IS NOT NULL THEN $3
                ELSE trial_ends_at
            END,
            trial_used = COALESCE($4, trial_used),
            discount_pct = COALESCE($5, discount_pct),
            admin_notes = COALESCE($6, admin_notes),
            admin_override = COALESCE($8, admin_override),
            seat_count = CASE
                WHEN $9::int IS NOT NULL THEN $9
                WHEN seat_count IS NULL AND COALESCE($1, subscription_tier) IN ('teams', 'business') THEN 3
                ELSE seat_count
            END
        WHERE id = $7
        "#,
    )
    .bind(&body.tier)
    .bind(body.clear_trial.unwrap_or(false))
    .bind(body.trial_ends_at)
    .bind(body.trial_used)
    .bind(body.discount_pct)
    .bind(&body.admin_notes)
    .bind(user_id)
    .bind(body.admin_override)
    .bind(body.seat_count)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to patch user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    write_audit(
        &pool,
        &admin_email,
        Some(user_id),
        "patch_user",
        json!({
            "tier": body.tier,
            "trial_ends_at": body.trial_ends_at,
            "trial_used": body.trial_used,
            "discount_pct": body.discount_pct,
            "admin_override": body.admin_override,
            "old_tier": old_tier,
        }),
    )
    .await;

    notifier.notify(user_id, "token_invalidated".to_string());
    info!(admin = %admin_email, user = %user_id, "Admin patched user");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Ban / unban ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BanRequest {
    reason: String,
}

pub async fn ban_user(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<BanRequest>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query(
        "UPDATE users SET is_banned = TRUE, ban_reason = $1, banned_at = now() WHERE id = $2",
    )
    .bind(&body.reason)
    .bind(user_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to ban user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    write_audit(
        &pool,
        &admin_email,
        Some(user_id),
        "ban",
        json!({"reason": body.reason}),
    )
    .await;

    notifier.notify(user_id, "token_invalidated".to_string());
    info!(admin = %admin_email, user = %user_id, reason = %body.reason, "User banned");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unban_user(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query(
        "UPDATE users SET is_banned = FALSE, ban_reason = NULL, banned_at = NULL WHERE id = $1",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to unban user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    write_audit(&pool, &admin_email, Some(user_id), "unban", json!({})).await;

    notifier.notify(user_id, "token_invalidated".to_string());
    info!(admin = %admin_email, user = %user_id, "User unbanned");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete / restore ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteQuery {
    /// When true, hard-delete immediately. Otherwise mark deleted_at (soft).
    force: Option<bool>,
}

#[derive(Deserialize)]
pub struct DeleteBody {
    reason: Option<String>,
}

/// DELETE /v1/admin/users/:id        → soft delete
/// DELETE /v1/admin/users/:id?force=true → hard delete (returns 409 if FK blocks)
pub async fn delete_user(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(user_id): Path<Uuid>,
    Query(q): Query<DeleteQuery>,
    Json(body): Json<DeleteBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let force = q.force.unwrap_or(false);

    let current = sqlx::query_as::<_, (String, Option<DateTime<Utc>>)>(
        "SELECT email, deleted_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch user before delete");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "fetch_failed"})))
    })?
    .ok_or((StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))))?;

    if force {
        // Hard delete. May fail on FK RESTRICT constraints (teams.owner_id,
        // audit_logs.actor_id, team_vault_*.updated_by, terminal_sessions.host_user_id).
        // Surface a structured 409 with the constraint name so the dashboard can
        // explain what blocks the purge.
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                write_audit(
                    &pool,
                    &admin_email,
                    None, // target is gone — store id in detail instead
                    "delete_user_force",
                    json!({
                        "user_id": user_id,
                        "email": current.0,
                        "reason": body.reason,
                    }),
                )
                .await;
                notifier.notify(user_id, "token_invalidated".to_string());
                info!(admin = %admin_email, user = %user_id, "User hard-deleted");
                Ok((StatusCode::NO_CONTENT, Json(json!({}))))
            }
            Ok(_) => Err((StatusCode::NOT_FOUND, Json(json!({"error": "not_found"})))),
            Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23503") => {
                let constraint = db_err.constraint().unwrap_or("unknown").to_string();
                error!(constraint = %constraint, user = %user_id, "Hard delete blocked by FK");
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "fk_blocks_delete",
                        "constraint": constraint,
                        "message": "User cannot be hard-deleted while referenced by other rows. Soft-delete instead or remove the references first.",
                    })),
                ))
            }
            Err(e) => {
                error!(error = %e, "Hard delete failed");
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "delete_failed"})),
                ))
            }
        }
    } else {
        // Soft delete: mark deleted_at, lock the account. PII intact for restore.
        if current.1.is_some() {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error": "already_deleted"})),
            ));
        }

        sqlx::query(
            "UPDATE users SET deleted_at = now(), deletion_reason = $1, deleted_by = $2 WHERE id = $3",
        )
        .bind(body.reason.as_deref())
        .bind(&admin_email)
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to soft-delete user");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "delete_failed"})))
        })?;

        write_audit(
            &pool,
            &admin_email,
            Some(user_id),
            "delete_user_soft",
            json!({"reason": body.reason, "email": current.0}),
        )
        .await;

        notifier.notify(user_id, "token_invalidated".to_string());
        info!(admin = %admin_email, user = %user_id, "User soft-deleted");
        Ok((StatusCode::NO_CONTENT, Json(json!({}))))
    }
}

/// POST /v1/admin/users/:id/restore — clear deleted_at within grace period.
pub async fn restore_user(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query(
        "UPDATE users SET deleted_at = NULL, deletion_reason = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to restore user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    write_audit(&pool, &admin_email, Some(user_id), "restore_user", json!({})).await;
    info!(admin = %admin_email, user = %user_id, "User restored");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Extend trial ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ExtendTrialRequest {
    days: i64,
}

pub async fn extend_trial(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<ExtendTrialRequest>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query(
        r#"
        UPDATE users SET
            trial_ends_at = GREATEST(COALESCE(trial_ends_at, now()), now()) + ($1 * interval '1 day'),
            trial_used = FALSE
        WHERE id = $2
        "#,
    )
    .bind(body.days)
    .bind(user_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to extend trial");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    write_audit(
        &pool,
        &admin_email,
        Some(user_id),
        "extend_trial",
        json!({"days": body.days}),
    )
    .await;

    notifier.notify(user_id, "token_invalidated".to_string());
    info!(admin = %admin_email, user = %user_id, days = body.days, "Trial extended");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Devices ──────────────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    device_id: String,
    size_bytes: i32,
    updated_at: DateTime<Utc>,
    metadata: Option<Value>,
}

pub async fn list_devices(
    State(pool): State<PgPool>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<DeviceRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT device_id, size_bytes, updated_at, metadata FROM sync_blobs WHERE user_id = $1 ORDER BY updated_at DESC",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list devices");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

// ─── Feature flags ────────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct FlagRow {
    flag: String,
    enabled: bool,
    set_by: String,
    set_at: DateTime<Utc>,
}

pub async fn list_flags(
    State(pool): State<PgPool>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<FlagRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, FlagRow>(
        "SELECT flag, enabled, set_by, set_at FROM user_feature_flags WHERE user_id = $1 ORDER BY flag",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list flags");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct SetFlagRequest {
    enabled: bool,
}

pub async fn set_flag(
    State(pool): State<PgPool>,
    Extension(AdminEmail(admin_email)): Extension<AdminEmail>,
    Path((user_id, flag)): Path<(Uuid, String)>,
    Json(body): Json<SetFlagRequest>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query(
        r#"
        INSERT INTO user_feature_flags (user_id, flag, enabled, set_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, flag) DO UPDATE SET enabled = $3, set_by = $4, set_at = now()
        "#,
    )
    .bind(user_id)
    .bind(&flag)
    .bind(body.enabled)
    .bind(&admin_email)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to set flag");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    write_audit(
        &pool,
        &admin_email,
        Some(user_id),
        "set_flag",
        json!({"flag": flag, "enabled": body.enabled}),
    )
    .await;

    info!(admin = %admin_email, user = %user_id, flag = %flag, enabled = body.enabled, "Feature flag set");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Churn history ────────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct ChurnRow {
    id: Uuid,
    user_id: Uuid,
    from_tier: String,
    to_tier: String,
    reason: Option<String>,
    created_at: DateTime<Utc>,
}

pub async fn list_user_churn(
    State(pool): State<PgPool>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<ChurnRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, ChurnRow>(
        "SELECT id, user_id, from_tier, to_tier, reason, created_at FROM churn_events WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list user churn");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

// ─── Audit log ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditQuery {
    target_id: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditRow {
    id: Uuid,
    admin_email: String,
    target_id: Option<Uuid>,
    action: String,
    detail: Value,
    created_at: DateTime<Utc>,
}

pub async fn list_audit_log(
    State(pool): State<PgPool>,
    Query(params): Query<AuditQuery>,
) -> Result<Json<Vec<AuditRow>>, StatusCode> {
    let limit = params.limit.unwrap_or(100).min(500);

    let rows = sqlx::query_as::<_, AuditRow>(
        r#"
        SELECT id, admin_email, target_id, action, detail, created_at
        FROM admin_audit_log
        WHERE ($1::uuid IS NULL OR target_id = $1)
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(params.target_id)
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list audit log");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

// ─── Global churn ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ChurnQuery {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

pub async fn list_churn(
    State(pool): State<PgPool>,
    Query(params): Query<ChurnQuery>,
) -> Result<Json<Vec<ChurnRow>>, StatusCode> {
    let from = params.from.unwrap_or_else(|| Utc::now() - Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let rows = sqlx::query_as::<_, ChurnRow>(
        r#"
        SELECT id, user_id, from_tier, to_tier, reason, created_at
        FROM churn_events
        WHERE created_at >= $1 AND created_at <= $2
        ORDER BY created_at DESC
        "#,
    )
    .bind(from)
    .bind(to)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list churn events");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

// ─── Presence (live online users) ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct PresenceResponse {
    online: Vec<Uuid>,
    count: usize,
}

/// GET /v1/admin/presence — snapshot of users with at least one active sync SSE.
pub async fn get_presence(
    Extension(presence): Extension<PresenceMap>,
) -> Json<PresenceResponse> {
    let online: Vec<Uuid> = presence.iter().map(|e| *e.key()).collect();
    let count = online.len();
    Json(PresenceResponse { online, count })
}

// ─── CSV export ───────────────────────────────────────────────────────────────

pub async fn export_users_csv(State(pool): State<PgPool>) -> Result<Response<Body>, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<DateTime<Utc>>, bool, bool, DateTime<Utc>, Option<String>)>(
        r#"
        SELECT u.id, u.email, u.subscription_tier, u.trial_ends_at, u.trial_used, u.is_banned,
               u.created_at, u.ls_customer_id
        FROM users u
        ORDER BY u.created_at DESC
        "#,
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch users for CSV export");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut csv = String::from("id,email,tier,trial_ends_at,trial_used,is_banned,created_at,ls_customer_id\n");
    for row in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            row.0,
            row.1,
            row.2,
            row.3.map(|t| t.to_rfc3339()).unwrap_or_default(),
            row.4,
            row.5,
            row.6.to_rfc3339(),
            row.7.unwrap_or_default(),
        ));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"users.csv\"",
        )
        .body(Body::from(csv))
        .unwrap())
}

// ─── Handler-body characterization tests ──────────────────────────────────────

#[cfg(test)]
mod admin_handler_tests {
    //! DB-backed characterization of the admin handler bodies. These handlers
    //! carry no inline authz — the admin surface is gated by the `require_admin_key`
    //! middleware (covered separately). Here we invoke each handler directly and
    //! assert (a) the DB row mutation and (b) the returned StatusCode, including
    //! not-found / conflict paths. Requires `TEST_DATABASE_URL`; otherwise skips.
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_team, seed_user, set_user_tier, set_user_trial};

    fn admin() -> Extension<AdminEmail> {
        Extension(AdminEmail("admin@test.local".to_string()))
    }

    fn notifier() -> Extension<SyncNotifier> {
        Extension(SyncNotifier::new())
    }

    async fn banned_row(pool: &PgPool, id: Uuid) -> (bool, Option<String>, Option<DateTime<Utc>>) {
        sqlx::query_as::<_, (bool, Option<String>, Option<DateTime<Utc>>)>(
            "SELECT is_banned, ban_reason, banned_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn tier_of(pool: &PgPool, id: Uuid) -> String {
        sqlx::query_scalar::<_, String>("SELECT subscription_tier FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn seats_of(pool: &PgPool, id: Uuid) -> Option<i32> {
        sqlx::query_scalar::<_, Option<i32>>("SELECT seat_count FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn trial_of(pool: &PgPool, id: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            "SELECT trial_ends_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn deleted_at_of(pool: &PgPool, id: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar::<_, Option<DateTime<Utc>>>("SELECT deleted_at FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn user_exists(pool: &PgPool, id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn churn_rows(pool: &PgPool, id: Uuid) -> Vec<(String, String, Option<String>)> {
        sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT from_tier, to_tier, reason FROM churn_events WHERE user_id = $1",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    fn patch_defaults() -> PatchUserRequest {
        PatchUserRequest {
            tier: None,
            trial_ends_at: None,
            clear_trial: None,
            trial_used: None,
            discount_pct: None,
            admin_notes: None,
            admin_override: None,
            seat_count: None,
        }
    }

    // ── Ban / unban ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ban_user_sets_banned_flag_reason_and_timestamp() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = ban_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(BanRequest {
                reason: "spam".to_string(),
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        let (is_banned, reason, banned_at) = banned_row(&pool, user).await;
        assert!(is_banned);
        assert_eq!(reason.as_deref(), Some("spam"));
        assert!(banned_at.is_some());
    }

    #[tokio::test]
    async fn ban_user_not_found_for_unknown_user() {
        let pool = test_pool_or_skip!();

        let res = ban_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(Uuid::new_v4()),
            Json(BanRequest {
                reason: "spam".to_string(),
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unban_user_clears_banned_flag_reason_and_timestamp() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        ban_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(BanRequest {
                reason: "spam".to_string(),
            }),
        )
        .await
        .unwrap();

        let res = unban_user(State(pool.clone()), admin(), notifier(), Path(user)).await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        let (is_banned, reason, banned_at) = banned_row(&pool, user).await;
        assert!(!is_banned);
        assert!(reason.is_none());
        assert!(banned_at.is_none());
    }

    #[tokio::test]
    async fn unban_user_not_found_for_unknown_user() {
        let pool = test_pool_or_skip!();

        let res = unban_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(Uuid::new_v4()),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    // ── Tier override / seat grants (patch_user) ─────────────────────────────

    #[tokio::test]
    async fn patch_user_updates_tier_and_defaults_seats_for_teams() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await; // seeds tier 'free', seat_count NULL

        let res = patch_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(PatchUserRequest {
                tier: Some("teams".to_string()),
                ..patch_defaults()
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(tier_of(&pool, user).await, "teams");
        // NULL seat_count with a teams/business tier defaults to 3.
        assert_eq!(seats_of(&pool, user).await, Some(3));
    }

    #[tokio::test]
    async fn patch_user_sets_explicit_seat_count() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = patch_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(PatchUserRequest {
                seat_count: Some(7),
                ..patch_defaults()
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(seats_of(&pool, user).await, Some(7));
    }

    #[tokio::test]
    async fn patch_user_downgrade_records_churn_event() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        set_user_tier(&pool, user, "business").await;

        let res = patch_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(PatchUserRequest {
                tier: Some("free".to_string()),
                ..patch_defaults()
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(tier_of(&pool, user).await, "free");
        let churn = churn_rows(&pool, user).await;
        assert_eq!(churn.len(), 1);
        assert_eq!(churn[0].0, "business");
        assert_eq!(churn[0].1, "free");
        assert_eq!(churn[0].2.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn patch_user_upgrade_records_no_churn_event() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await; // 'free'

        let res = patch_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(PatchUserRequest {
                tier: Some("pro".to_string()),
                ..patch_defaults()
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(tier_of(&pool, user).await, "pro");
        assert!(churn_rows(&pool, user).await.is_empty());
    }

    #[tokio::test]
    async fn patch_user_clear_trial_nulls_trial_ends_at() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        set_user_trial(&pool, user, 30).await;
        assert!(trial_of(&pool, user).await.is_some());

        let res = patch_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(PatchUserRequest {
                clear_trial: Some(true),
                ..patch_defaults()
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert!(trial_of(&pool, user).await.is_none());
    }

    #[tokio::test]
    async fn patch_user_not_found_for_unknown_user() {
        let pool = test_pool_or_skip!();

        let res = patch_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(Uuid::new_v4()),
            Json(PatchUserRequest {
                tier: Some("pro".to_string()),
                ..patch_defaults()
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    // ── Extend trial ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn extend_trial_sets_future_trial_ends_at_and_clears_used() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = extend_trial(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Json(ExtendTrialRequest { days: 14 }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        let ends = trial_of(&pool, user).await.expect("trial set");
        let delta = ends - Utc::now();
        assert!(
            delta > Duration::days(13) && delta < Duration::days(15),
            "trial should end ~14 days out, got {delta}"
        );
        let used = sqlx::query_scalar::<_, bool>("SELECT trial_used FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!used);
    }

    #[tokio::test]
    async fn extend_trial_not_found_for_unknown_user() {
        let pool = test_pool_or_skip!();

        let res = extend_trial(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(Uuid::new_v4()),
            Json(ExtendTrialRequest { days: 14 }),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    // ── Feature flags ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_flag_inserts_then_upserts() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = set_flag(
            State(pool.clone()),
            admin(),
            Path((user, "beta".to_string())),
            Json(SetFlagRequest { enabled: true }),
        )
        .await;
        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        let enabled = sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM user_feature_flags WHERE user_id = $1 AND flag = 'beta'",
        )
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(enabled);

        let res = set_flag(
            State(pool.clone()),
            admin(),
            Path((user, "beta".to_string())),
            Json(SetFlagRequest { enabled: false }),
        )
        .await;
        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        let (enabled, count) = sqlx::query_as::<_, (bool, i64)>(
            "SELECT bool_or(enabled), COUNT(*) FROM user_feature_flags WHERE user_id = $1 AND flag = 'beta'",
        )
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!enabled);
        assert_eq!(count, 1); // upsert, not a second row
    }

    // ── Delete / restore ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_user_soft_marks_deleted_at() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Query(DeleteQuery { force: None }),
            Json(DeleteBody {
                reason: Some("cleanup".to_string()),
            }),
        )
        .await;

        let (status, _) = res.expect("soft delete ok");
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(deleted_at_of(&pool, user).await.is_some());
        assert!(user_exists(&pool, user).await); // soft, row still present
    }

    #[tokio::test]
    async fn delete_user_soft_conflict_when_already_deleted() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let (_, _body) = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Query(DeleteQuery { force: None }),
            Json(DeleteBody { reason: None }),
        )
        .await
        .expect("first soft delete ok");

        let res = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Query(DeleteQuery { force: None }),
            Json(DeleteBody { reason: None }),
        )
        .await;

        let (status, _) = res.expect_err("second delete should conflict");
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn delete_user_not_found_for_unknown_user() {
        let pool = test_pool_or_skip!();

        let res = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(Uuid::new_v4()),
            Query(DeleteQuery { force: None }),
            Json(DeleteBody { reason: None }),
        )
        .await;

        let (status, _) = res.expect_err("unknown user should 404");
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_user_force_hard_deletes_row() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Query(DeleteQuery { force: Some(true) }),
            Json(DeleteBody { reason: None }),
        )
        .await;

        let (status, _) = res.expect("hard delete ok");
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!user_exists(&pool, user).await); // row gone
    }

    #[tokio::test]
    async fn delete_user_force_conflict_when_referenced_by_fk() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        seed_team(&pool, owner).await; // teams.owner_id FK RESTRICT blocks the purge

        let res = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(owner),
            Query(DeleteQuery { force: Some(true) }),
            Json(DeleteBody { reason: None }),
        )
        .await;

        let (status, _) = res.expect_err("fk should block hard delete");
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(user_exists(&pool, owner).await); // still present
    }

    #[tokio::test]
    async fn restore_user_clears_deleted_at() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let (_, _body) = delete_user(
            State(pool.clone()),
            admin(),
            notifier(),
            Path(user),
            Query(DeleteQuery { force: None }),
            Json(DeleteBody { reason: None }),
        )
        .await
        .expect("soft delete ok");
        assert!(deleted_at_of(&pool, user).await.is_some());

        let res = restore_user(State(pool.clone()), admin(), Path(user)).await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert!(deleted_at_of(&pool, user).await.is_none());
    }

    #[tokio::test]
    async fn restore_user_not_found_when_not_deleted() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await; // never deleted

        let res = restore_user(State(pool.clone()), admin(), Path(user)).await;

        // No matching row (WHERE deleted_at IS NOT NULL) → rows_affected 0 → 404.
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    // ── last_seen_on surfacing ───────────────────────────────────────────────
    // These hold the last_seen lock: they write last_seen_on, and the activity
    // count tests assert on before/after deltas of whole-table aggregates.

    fn users_query(search: &str) -> Query<UsersQuery> {
        Query(UsersQuery {
            page: None,
            limit: None,
            search: Some(search.to_string()),
            tier: None,
            banned: None,
            deleted: None,
            sort: None,
            dir: None,
        })
    }

    /// Seed a user whose email carries `tag`, so a test can select exactly its
    /// own rows out of a shared database via the `search` filter.
    async fn seed_tagged_user(pool: &PgPool, tag: &str, name: &str, seen_days_ago: Option<i32>) -> Uuid {
        let id = Uuid::new_v4();
        let handle = crate::handles::generate_unique_handle(pool).await;
        sqlx::query(
            "INSERT INTO users (id, email, account_id, auth_hash, public_key, display_name, last_seen_on, handle)
             VALUES ($1, $2, $3, 'test-hash', 'test-pubkey', 'Test User',
                     CASE WHEN $4::int IS NULL THEN NULL ELSE current_date - $4::int END, $5)",
        )
        .bind(id)
        .bind(format!("{name}-{tag}@test.local"))
        .bind(Uuid::new_v4())
        .bind(seen_days_ago)
        .bind(&handle)
        .execute(pool)
        .await
        .expect("seed tagged user");
        id
    }

    async fn listed_ids(pool: &PgPool, q: Query<UsersQuery>) -> Vec<String> {
        let body = list_users(State(pool.clone()), q).await.expect("list users").0;
        body["users"]
            .as_array()
            .expect("users array")
            .iter()
            .map(|u| u["id"].as_str().expect("id").to_string())
            .collect()
    }

    fn sorted_query(search: &str, sort: &str, dir: &str) -> Query<UsersQuery> {
        let mut q = users_query(search);
        q.0.sort = Some(sort.to_string());
        q.0.dir = Some(dir.to_string());
        q
    }

    #[tokio::test]
    async fn list_users_sorted_by_last_seen_desc_puts_recent_first_nulls_last() {
        let _guard = crate::test_support::last_seen_lock().await;
        let pool = test_pool_or_skip!();
        let tag = Uuid::new_v4().to_string();
        let recent = seed_tagged_user(&pool, &tag, "recent", Some(0)).await;
        let older = seed_tagged_user(&pool, &tag, "older", Some(40)).await;
        let never = seed_tagged_user(&pool, &tag, "never", None).await;

        let ids = listed_ids(&pool, sorted_query(&tag, "last_seen_on", "desc")).await;

        assert_eq!(
            ids,
            vec![recent.to_string(), older.to_string(), never.to_string()],
            "never-seen sorts last, not as the most recent"
        );
    }

    #[tokio::test]
    async fn list_users_sorted_by_last_seen_asc_puts_oldest_first_nulls_last() {
        let _guard = crate::test_support::last_seen_lock().await;
        let pool = test_pool_or_skip!();
        let tag = Uuid::new_v4().to_string();
        let recent = seed_tagged_user(&pool, &tag, "recent", Some(0)).await;
        let older = seed_tagged_user(&pool, &tag, "older", Some(40)).await;
        let never = seed_tagged_user(&pool, &tag, "never", None).await;

        let ids = listed_ids(&pool, sorted_query(&tag, "last_seen_on", "asc")).await;

        assert_eq!(
            ids,
            vec![older.to_string(), recent.to_string(), never.to_string()],
            "oldest first for stale-hunting; unknown still sorts last, not first"
        );
    }

    #[tokio::test]
    async fn list_users_rejects_unknown_sort_column() {
        let pool = test_pool_or_skip!();

        let res = list_users(State(pool.clone()), sorted_query("nobody", "email; DROP TABLE users", "desc")).await;

        assert_eq!(res.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_users_rejects_unknown_sort_direction() {
        let pool = test_pool_or_skip!();

        let res = list_users(State(pool.clone()), sorted_query("nobody", "last_seen_on", "sideways")).await;

        assert_eq!(res.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_users_paginates_deterministically_when_sort_key_ties() {
        let _guard = crate::test_support::last_seen_lock().await;
        let pool = test_pool_or_skip!();
        let tag = Uuid::new_v4().to_string();
        // Four users sharing one last_seen_on: without a unique tiebreak, LIMIT
        // OFFSET paging over equal keys can repeat or skip rows between pages.
        for n in 0..4 {
            seed_tagged_user(&pool, &tag, &format!("tie{n}"), Some(5)).await;
        }

        let mut seen = Vec::new();
        for page in 1..=2 {
            let mut q = sorted_query(&tag, "last_seen_on", "desc");
            q.0.limit = Some(2);
            q.0.page = Some(page);
            seen.extend(listed_ids(&pool, q).await);
        }

        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(seen.len(), 4, "both pages full");
        assert_eq!(unique.len(), 4, "no row repeated across pages");
    }

    #[tokio::test]
    async fn list_users_returns_last_seen_on() {
        let _guard = crate::test_support::last_seen_lock().await;
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        sqlx::query("UPDATE users SET last_seen_on = current_date - 3 WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .expect("set last_seen_on");

        let body = list_users(State(pool.clone()), users_query(&format!("{user}@test.local")))
            .await
            .expect("list users")
            .0;

        let expected: chrono::NaiveDate = sqlx::query_scalar("SELECT current_date - 3")
            .fetch_one(&pool)
            .await
            .expect("expected date");
        assert_eq!(
            body["users"][0]["last_seen_on"].as_str(),
            Some(expected.to_string().as_str())
        );
    }

    #[tokio::test]
    async fn list_users_reports_null_last_seen_on_for_never_seen_user() {
        let _guard = crate::test_support::last_seen_lock().await;
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await; // never stamped

        let body = list_users(State(pool.clone()), users_query(&format!("{user}@test.local")))
            .await
            .expect("list users")
            .0;

        assert!(
            body["users"][0]["last_seen_on"].is_null(),
            "never-seen user must be null, not a fabricated date"
        );
    }

    #[tokio::test]
    async fn get_user_returns_last_seen_on() {
        let _guard = crate::test_support::last_seen_lock().await;
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        sqlx::query("UPDATE users SET last_seen_on = current_date WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .expect("set last_seen_on");

        let detail = get_user(State(pool.clone()), Path(user)).await.expect("get user").0;
        let body = serde_json::to_value(&detail).expect("serialize detail");

        let today: chrono::NaiveDate = sqlx::query_scalar("SELECT current_date")
            .fetch_one(&pool)
            .await
            .expect("current_date");
        assert_eq!(body["last_seen_on"].as_str(), Some(today.to_string().as_str()));
    }
}
