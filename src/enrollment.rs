use axum::http::StatusCode;
use base64::Engine;
use rand::RngCore;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use tracing::{error, warn};
use uuid::Uuid;

use crate::permissions::PERM_INVITE_MEMBERS;
use crate::routes::audit::write_audit_event;
use crate::routes::invitations::{admit_member, notify_member_added};
use crate::routes::team_enrollment::{EnrollError, TokenRow};
use crate::routes::team_grants::ensure_public_key;
use crate::routes::teams::ensure_seat_available;
use crate::sync_notifier::{notify_team_permission_holders, SyncNotifier};
use crate::team_authority::lock_billing_owner;
use crate::team_plan::team_locked;

const DEFAULT_ROLE: &str = "member";

pub(crate) fn role_or_default(role: Option<&str>) -> &str {
    role.unwrap_or(DEFAULT_ROLE)
}

pub fn mint_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReason {
    Approval,
    EmailUnverified,
    SeatLimit,
}

impl PendingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            PendingReason::Approval => "approval",
            PendingReason::EmailUnverified => "email_unverified",
            PendingReason::SeatLimit => "seat_limit",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        [PendingReason::Approval, PendingReason::EmailUnverified, PendingReason::SeatLimit]
            .into_iter()
            .find(|reason| reason.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admit,
    Pending(PendingReason),
    DomainMismatch,
}

#[derive(Debug, Clone)]
pub struct Guard {
    pub allowed_domains: Vec<String>,
    pub require_approval: bool,
}

pub fn domain_allowed(guard: &Guard, email: &str) -> bool {
    if guard.allowed_domains.is_empty() {
        return true;
    }
    email
        .rsplit_once('@')
        .map(|(_, d)| d.to_lowercase())
        .is_some_and(|d| guard.allowed_domains.contains(&d))
}

pub fn admission(guard: &Guard, email: &str, email_proven: bool, seat_available: bool) -> Admission {
    if !domain_allowed(guard, email) {
        return Admission::DomainMismatch;
    }
    if guard.require_approval {
        let proof_missing = !guard.allowed_domains.is_empty() && !email_proven;
        return Admission::Pending(if proof_missing { PendingReason::EmailUnverified } else { PendingReason::Approval });
    }
    if !email_proven {
        return Admission::Pending(PendingReason::EmailUnverified);
    }
    if !seat_available {
        return Admission::Pending(PendingReason::SeatLimit);
    }
    Admission::Admit
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemOutcome {
    Member,
    Admitted,
    Pending(PendingReason),
}

impl Serialize for RedeemOutcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (status, reason) = match self {
            RedeemOutcome::Member => ("member", None),
            RedeemOutcome::Admitted => ("admitted", None),
            RedeemOutcome::Pending(reason) => ("pending", Some(reason.as_str())),
        };
        let mut out = serializer.serialize_struct("RedeemOutcome", 1 + usize::from(reason.is_some()))?;
        out.serialize_field("status", status)?;
        if let Some(reason) = reason {
            out.serialize_field("reason", reason)?;
        }
        out.end()
    }
}

#[derive(serde::Serialize)]
pub struct RedeemResponse {
    #[serde(flatten)]
    pub outcome: RedeemOutcome,
    pub team_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct PendingRequest {
    user_id: Uuid,
    token_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct TokenState {
    role: String,
    allowed_domains: Vec<String>,
    require_approval: bool,
    created_by: Option<Uuid>,
    live: bool,
}

pub(crate) async fn audit_request(pool: &PgPool, team_id: Uuid, actor: Uuid, action: &str, request_id: Uuid, user_id: Uuid) {
    write_audit_event(
        pool.clone(),
        team_id,
        actor,
        action,
        Some("join_request"),
        Some(request_id.to_string()),
        None,
        Some(json!({ "user_id": user_id })),
    )
    .await;
}

pub(crate) async fn notify_join_requests_changed(pool: &PgPool, notifier: &SyncNotifier, team_id: Uuid) {
    notify_team_permission_holders(pool, notifier, team_id, PERM_INVITE_MEMBERS, format!("join_requests:{team_id}")).await;
}

pub(crate) async fn decide_pending(
    conn: &mut PgConnection,
    request_id: Uuid,
    team_id: Uuid,
    status: &str,
    decided_by: Option<Uuid>,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE team_join_requests SET status = $3, reason = NULL, decided_by = $4, decided_at = now() \
         WHERE id = $1 AND team_id = $2 AND status = 'pending' RETURNING user_id",
    )
    .bind(request_id)
    .bind(team_id)
    .bind(status)
    .bind(decided_by)
    .fetch_optional(conn)
    .await
}

async fn is_member(conn: &mut PgConnection, team_id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)")
        .bind(team_id)
        .bind(user_id)
        .fetch_one(conn)
        .await
}

async fn user_identity(conn: &mut PgConnection, user_id: Uuid) -> Result<(String, bool), sqlx::Error> {
    sqlx::query_as("SELECT email, email_proven_at IS NOT NULL FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(conn)
        .await
}

async fn seat_available(pool: &PgPool, owner_id: Uuid, user_id: Uuid) -> Result<bool, EnrollError> {
    match ensure_seat_available(pool, owner_id, Some(user_id)).await {
        Ok(()) => Ok(true),
        Err(StatusCode::PAYMENT_REQUIRED) => Ok(false),
        Err(status) => Err(status.into()),
    }
}

fn proof_available(guard: &Guard, proven: bool) -> bool {
    proven || (guard.require_approval && !crate::email::delivery_configured())
}

pub(crate) async fn redeem_for(
    pool: &PgPool,
    notifier: &SyncNotifier,
    token: &TokenRow,
    user_id: Uuid,
    public_key: Option<&str>,
) -> Result<RedeemOutcome, EnrollError> {
    let mut conn = pool.acquire().await?;
    if is_member(&mut conn, token.team_id, user_id).await? {
        return Ok(RedeemOutcome::Member);
    }
    let (email, proven) = user_identity(&mut conn, user_id).await?;
    let guard = token.guard();
    let first = admission(&guard, &email, proof_available(&guard, proven), true);
    let reason = match first {
        Admission::DomainMismatch => return Err(EnrollError::DomainMismatch),
        Admission::Pending(reason) => reason,
        Admission::Admit => PendingReason::Approval,
    };
    ensure_public_key(&mut conn, user_id, public_key).await?;
    let (request_id, inserted, prior) = sqlx::query_as::<_, (Uuid, bool, Option<String>)>(
        "WITH prior AS (SELECT reason FROM team_join_requests WHERE team_id = $1 AND user_id = $2 AND status = 'pending') \
         INSERT INTO team_join_requests (team_id, user_id, token_id, status, reason) VALUES ($1, $2, $3, 'pending', $4) \
         ON CONFLICT (team_id, user_id) WHERE status = 'pending' \
         DO UPDATE SET reason = EXCLUDED.reason, token_id = EXCLUDED.token_id \
         RETURNING id, (xmax = 0), (SELECT reason FROM prior)",
    )
    .bind(token.team_id)
    .bind(user_id)
    .bind(token.id)
    .bind(reason.as_str())
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query("UPDATE team_enrollment_tokens SET last_used_at = now() WHERE id = $1")
        .bind(token.id)
        .execute(&mut *conn)
        .await?;
    drop(conn);

    let outcome = match first {
        Admission::Pending(reason) => RedeemOutcome::Pending(reason),
        _ => match try_admit(pool, notifier, request_id, None).await {
            Err(EnrollError::NotFound) => settled_state(pool, token.team_id, user_id).await?,
            other => other?,
        },
    };
    if let RedeemOutcome::Pending(reason) = outcome {
        if inserted {
            audit_request(pool, token.team_id, user_id, "join_request.created", request_id, user_id).await;
        }
        if prior.as_deref() != Some(reason.as_str()) {
            notify_join_requests_changed(pool, notifier, token.team_id).await;
        }
    }
    Ok(outcome)
}

async fn settled_state(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> Result<RedeemOutcome, EnrollError> {
    let mut conn = pool.acquire().await?;
    if is_member(&mut conn, team_id, user_id).await? {
        return Ok(RedeemOutcome::Member);
    }
    let reason = sqlx::query_scalar::<_, Option<String>>(
        "SELECT reason FROM team_join_requests WHERE team_id = $1 AND user_id = $2 AND status = 'pending'",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    reason
        .flatten()
        .as_deref()
        .and_then(PendingReason::from_db)
        .map(RedeemOutcome::Pending)
        .ok_or(EnrollError::NotFound)
}

pub(crate) async fn try_admit(
    pool: &PgPool,
    notifier: &SyncNotifier,
    request_id: Uuid,
    approved_by: Option<Uuid>,
) -> Result<RedeemOutcome, EnrollError> {
    let mut tx = pool.begin().await?;
    let team_id = sqlx::query_scalar::<_, Uuid>("SELECT team_id FROM team_join_requests WHERE id = $1 AND status = 'pending'")
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(EnrollError::NotFound)?;
    let owner_id = lock_billing_owner(&mut tx, team_id).await?;
    let PendingRequest { user_id, token_id } = sqlx::query_as::<_, PendingRequest>(
        "SELECT user_id, token_id FROM team_join_requests WHERE id = $1 AND team_id = $2 AND status = 'pending' FOR UPDATE",
    )
    .bind(request_id)
    .bind(team_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(EnrollError::NotFound)?;
    if team_locked(pool, team_id).await? {
        return Err(EnrollError::Unavailable);
    }

    if is_member(&mut tx, team_id, user_id).await? {
        decide_pending(&mut tx, request_id, team_id, "approved", approved_by).await?;
        tx.commit().await?;
        notify_join_requests_changed(pool, notifier, team_id).await;
        return Ok(RedeemOutcome::Member);
    }

    let token = sqlx::query_as::<_, TokenState>(
        "SELECT role, allowed_domains, require_approval, created_by, \
                (revoked_at IS NULL AND COALESCE(expires_at > now(), true)) AS live \
         FROM team_enrollment_tokens WHERE id = $1",
    )
    .bind(token_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (email, proven) = user_identity(&mut tx, user_id).await?;
    let (guard, proven) = match (&token, approved_by) {
        (token, Some(_)) => {
            let allowed_domains = token.as_ref().map(|t| t.allowed_domains.clone()).unwrap_or_default();
            let needs_proof = !allowed_domains.is_empty() && crate::email::delivery_configured();
            (Guard { allowed_domains, require_approval: false }, proven || !needs_proof)
        }
        (Some(token), None) if token.live => {
            let guard = Guard { allowed_domains: token.allowed_domains.clone(), require_approval: token.require_approval };
            let proven = proof_available(&guard, proven);
            (guard, proven)
        }
        (_, None) => (Guard { allowed_domains: Vec::new(), require_approval: true }, proven),
    };

    match admission(&guard, &email, proven, seat_available(pool, owner_id, user_id).await?) {
        Admission::DomainMismatch => Err(EnrollError::DomainMismatch),
        Admission::Pending(reason) => {
            let changed = sqlx::query("UPDATE team_join_requests SET reason = $2 WHERE id = $1 AND reason IS DISTINCT FROM $2")
                .bind(request_id)
                .bind(reason.as_str())
                .execute(&mut *tx)
                .await?
                .rows_affected()
                > 0;
            tx.commit().await?;
            if changed {
                notify_join_requests_changed(pool, notifier, team_id).await;
            }
            if approved_by.is_some() && reason == PendingReason::SeatLimit {
                return Err(EnrollError::NoSeat);
            }
            Ok(RedeemOutcome::Pending(reason))
        }
        Admission::Admit => {
            let role = role_or_default(token.as_ref().map(|t| t.role.as_str()));
            admit_member(&mut tx, team_id, user_id, token.as_ref().and_then(|t| t.created_by), role, &[], None).await?;
            decide_pending(&mut tx, request_id, team_id, "approved", approved_by).await?;
            tx.commit().await?;

            if let Some(admin) = approved_by {
                audit_request(pool, team_id, admin, "join_request.approved", request_id, user_id).await;
            }
            write_audit_event(
                pool.clone(),
                team_id,
                approved_by.unwrap_or(user_id),
                "member.admitted",
                Some("user"),
                Some(user_id.to_string()),
                None,
                Some(json!({ "via": "enrollment" })),
            )
            .await;
            notify_member_added(pool, notifier, team_id, user_id).await;
            notify_join_requests_changed(pool, notifier, team_id).await;
            Ok(RedeemOutcome::Admitted)
        }
    }
}

pub(crate) async fn admit_verified_requests(pool: &PgPool, notifier: &SyncNotifier, user_id: Uuid) {
    let requests = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM team_join_requests WHERE user_id = $1 AND status = 'pending' AND reason = 'email_unverified'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        error!(error = %e, user_id = %user_id, "Failed to list join requests awaiting verification");
        Vec::new()
    });
    for request_id in requests {
        match try_admit(pool, notifier, request_id, None).await {
            Ok(_) => {}
            Err(err @ (EnrollError::DomainMismatch | EnrollError::NotFound | EnrollError::Unavailable)) => {
                warn!(?err, request_id = %request_id, "Join request not admitted after email verification");
            }
            Err(err) => error!(?err, request_id = %request_id, "Failed to admit a join request after email verification"),
        }
    }
}

fn is_hostname(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').count() >= 2
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub fn normalize_domains(input: &[String]) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = Vec::new();
    for raw in input {
        let domain = raw.trim().to_lowercase();
        let domain = domain.strip_prefix('@').unwrap_or(&domain).to_string();
        if !is_hostname(&domain) {
            return Err(());
        }
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(domains: &[&str], approval: bool) -> Guard {
        Guard { allowed_domains: domains.iter().map(|d| d.to_string()).collect(), require_approval: approval }
    }

    #[test]
    fn domain_guard_admits_only_exact_proven_matches_with_a_seat() {
        let g = guard(&["acme.com"], false);
        assert_eq!(admission(&g, "a@acme.com", true, true), Admission::Admit);
        assert_eq!(admission(&g, "A@ACME.COM", true, true), Admission::Admit);
        assert_eq!(admission(&g, "a@acme.com", false, true), Admission::Pending(PendingReason::EmailUnverified));
        assert_eq!(admission(&g, "a@acme.com", true, false), Admission::Pending(PendingReason::SeatLimit));
        assert_eq!(admission(&g, "a@gmail.com", true, true), Admission::DomainMismatch);
        assert_eq!(admission(&g, "a@sub.acme.com", true, true), Admission::DomainMismatch);
    }

    #[test]
    fn the_domain_is_the_part_after_the_last_at() {
        let g = guard(&["acme.com"], false);
        assert_eq!(admission(&g, "noat", true, true), Admission::DomainMismatch);
        assert_eq!(admission(&g, "a@b@acme.com", true, true), Admission::Admit);
    }

    #[test]
    fn approval_only_guard_makes_everyone_pending() {
        let g = guard(&[], true);
        assert_eq!(admission(&g, "a@gmail.com", true, true), Admission::Pending(PendingReason::Approval));
    }

    #[test]
    fn domain_mismatch_wins_over_approval() {
        let g = guard(&["acme.com"], true);
        assert_eq!(admission(&g, "a@gmail.com", true, true), Admission::DomainMismatch);
        assert_eq!(admission(&g, "a@acme.com", true, true), Admission::Pending(PendingReason::Approval));
        assert_eq!(admission(&g, "a@acme.com", false, true), Admission::Pending(PendingReason::EmailUnverified));
    }

    #[test]
    fn pending_reasons_match_the_database_values() {
        for (reason, value) in [
            (PendingReason::Approval, "approval"),
            (PendingReason::EmailUnverified, "email_unverified"),
            (PendingReason::SeatLimit, "seat_limit"),
        ] {
            assert_eq!(reason.as_str(), value);
            assert_eq!(PendingReason::from_db(value), Some(reason));
        }
        assert_eq!(PendingReason::from_db("other"), None);
    }

    #[test]
    fn normalize_domains_cleans_and_dedupes() {
        let input = vec![" @Acme.COM ".to_string(), "acme.com".to_string()];
        assert_eq!(normalize_domains(&input), Ok(vec!["acme.com".to_string()]));
    }

    #[test]
    fn normalize_domains_rejects_non_hostnames() {
        for bad in ["acme", "a b.com", "", "-a.com", "a-.com", "a..com", "a.com/x"] {
            assert!(normalize_domains(&[bad.to_string()]).is_err(), "{bad}");
        }
        assert!(normalize_domains(&[format!("{}.com", "a".repeat(64))]).is_err());
    }

    #[test]
    fn normalize_domains_accepts_punycode_and_rejects_a_trailing_dot() {
        assert_eq!(normalize_domains(&["xn--bcher-kva.example".to_string()]), Ok(vec!["xn--bcher-kva.example".to_string()]));
        assert!(normalize_domains(&["acme.com.".to_string()]).is_err());
    }

    #[test]
    fn mint_secret_is_43_url_safe_chars() {
        let s = mint_secret();
        assert_eq!(s.len(), 43);
        assert_ne!(s, mint_secret());
    }
}
