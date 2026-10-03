use axum::{extract::Request, middleware::Next, response::Response, Extension};
use std::{collections::{HashMap, VecDeque}, sync::Arc};
use tokio::sync::{broadcast, watch, Mutex};
use uuid::Uuid;
use serde::Serialize;

pub const BROADCAST_CAPACITY: usize = 512;
/// Maximum number of encrypted output messages kept per session for late-join replay.
pub const OUTPUT_HISTORY_MAX: usize = 500;

/// A live participant in a shared session. The name is resolved server-side
/// from `users.handle` — it is never supplied by the client, which is what
/// stops a participant naming themselves "Voltius Support" and what stops the
/// list carrying anyone's email address.
#[derive(Debug, Clone, Serialize)]
pub struct Participant {
    pub user_id: Uuid,
    pub handle: String,
    /// ALIAS for pre-0.26 clients. Value is the handle; there is no stored
    /// `display_name`. Delete this field in 0.27, and never repopulate it
    /// from anything.
    pub display_name: String,
}

impl Participant {
    pub fn new(user_id: Uuid, handle: String) -> Self {
        Self { user_id, display_name: handle.clone(), handle }
    }
}

pub struct SessionState {
    /// Vaults whose members are allowed to join (empty only for invite_link sessions)
    pub vault_ids: Vec<Uuid>,
    /// Role filter — empty means all roles; non-empty means only these roles can join
    pub allowed_roles: Vec<String>,
    /// Users granted access individually (issue #66). Authoritative for WS
    /// authorization; lost on restart along with the session itself.
    pub invitees: std::collections::HashSet<Uuid>,
    pub host_user_id: Uuid,
    pub host_public_key: String,
    pub visibility: String,
    /// Owner of the vault for vault-visibility sessions; None for invite_link sessions.
    /// Used to resolve the effective tier for participant cap enforcement.
    pub vault_owner_id: Option<Uuid>,
    pub participants: HashMap<Uuid, Participant>,
    pub control_holder: Uuid,
    pub pending_control_request: Option<Uuid>,
    pub tx: broadcast::Sender<String>,
    /// Ring buffer of recent encrypted output relay messages for late-join replay.
    /// Stored as-is (already encrypted); the server never sees plaintext.
    pub output_history: VecDeque<String>,
    /// Bumped when someone may have lost access; each attached socket re-runs admission.
    pub access_changed: watch::Sender<()>,
}

impl SessionState {
    pub fn recheck_access(&self) {
        self.access_changed.send_replace(());
    }
}

#[derive(Clone)]
pub struct TerminalManager {
    pub sessions: Arc<Mutex<HashMap<Uuid, SessionState>>>,
}

impl TerminalManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// `None` rechecks every live session.
    pub async fn recheck_sessions(&self, team: Option<Uuid>) {
        for state in self.sessions.lock().await.values() {
            if team.is_none_or(|t| state.vault_ids.contains(&t)) {
                state.recheck_access();
            }
        }
    }
}

/// `Some(None)` rechecks every session: a team write can cost View or Join, an account write the account.
fn recheck_scope(path: &str) -> Option<Option<Uuid>> {
    if let Some(rest) = path.strip_prefix("/v1/teams/") {
        return rest.split('/').next()?.parse().ok().map(Some);
    }
    (path.starts_with("/v1/admin/users/") || path == "/v1/auth/account").then_some(None)
}

pub async fn recheck_sessions_after_access_write(
    Extension(manager): Extension<TerminalManager>,
    req: Request,
    next: Next,
) -> Response {
    let scope = (!req.method().is_safe()).then(|| recheck_scope(req.uri().path())).flatten();
    let res = next.run(req).await;
    if let Some(team) = scope.filter(|_| res.status().is_success()) {
        manager.recheck_sessions(team).await;
    }
    res
}

#[cfg(test)]
impl TerminalManager {
    /// Registers a minimal live `direct` session so tests can exercise code
    /// that reads or mutates in-memory session state.
    pub async fn insert_test_session(&self, session_id: Uuid, host: Uuid) {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        self.sessions.lock().await.insert(
            session_id,
            SessionState {
                vault_ids: vec![],
                allowed_roles: vec![],
                invitees: std::collections::HashSet::new(),
                host_user_id: host,
                host_public_key: String::new(),
                visibility: "direct".to_string(),
                vault_owner_id: None,
                participants: HashMap::new(),
                control_holder: host,
                pending_control_request: None,
                tx,
                output_history: VecDeque::new(),
                access_changed: watch::channel(()).0,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        middleware::from_fn,
        Extension, Router,
    };
    use tower::ServiceExt;

    async fn vault_session(manager: &TerminalManager, team: Uuid) -> watch::Receiver<()> {
        let session_id = Uuid::new_v4();
        manager.insert_test_session(session_id, Uuid::new_v4()).await;
        let mut sessions = manager.sessions.lock().await;
        let state = sessions.get_mut(&session_id).unwrap();
        state.visibility = "vault".to_string();
        state.vault_ids = vec![team];
        state.access_changed.subscribe()
    }

    async fn send(manager: &TerminalManager, method: Method, path: &str, status: StatusCode) {
        let app = Router::new()
            .fallback(move || async move { status })
            .layer(from_fn(recheck_sessions_after_access_write))
            .layer(Extension(manager.clone()));
        let req = Request::builder().method(method).uri(path).body(Body::empty()).unwrap();
        app.oneshot(req).await.unwrap();
    }

    #[tokio::test]
    async fn a_successful_team_write_rechecks_only_that_teams_sessions() {
        let manager = TerminalManager::new();
        let (team, other) = (Uuid::new_v4(), Uuid::new_v4());
        let edited = vault_session(&manager, team).await;
        let untouched = vault_session(&manager, other).await;

        send(&manager, Method::PATCH, &format!("/v1/teams/{team}/roles/{}", Uuid::new_v4()), StatusCode::OK).await;

        assert!(edited.has_changed().unwrap());
        assert!(!untouched.has_changed().unwrap());
    }

    #[tokio::test]
    async fn reads_failed_writes_and_teamless_paths_recheck_nothing() {
        let manager = TerminalManager::new();
        let team = Uuid::new_v4();
        let rx = vault_session(&manager, team).await;
        let role_path = format!("/v1/teams/{team}/roles/{}", Uuid::new_v4());

        send(&manager, Method::GET, &role_path, StatusCode::OK).await;
        send(&manager, Method::PATCH, &role_path, StatusCode::FORBIDDEN).await;
        send(&manager, Method::PATCH, "/v1/teams", StatusCode::OK).await;
        send(&manager, Method::GET, &format!("/v1/admin/users/{}", Uuid::new_v4()), StatusCode::OK).await;
        send(&manager, Method::PUT, "/v1/auth/email", StatusCode::OK).await;

        assert!(!rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn account_writes_recheck_every_session() {
        let manager = TerminalManager::new();
        let user = Uuid::new_v4();
        for (method, path) in [
            (Method::POST, format!("/v1/admin/users/{user}/ban")),
            (Method::DELETE, format!("/v1/admin/users/{user}")),
            (Method::DELETE, "/v1/auth/account".to_string()),
        ] {
            let a = vault_session(&manager, Uuid::new_v4()).await;
            let b = vault_session(&manager, Uuid::new_v4()).await;

            send(&manager, method.clone(), &path, StatusCode::NO_CONTENT).await;

            assert!(a.has_changed().unwrap() && b.has_changed().unwrap(), "{method} {path}");
        }
    }

    #[tokio::test]
    async fn the_sweep_rechecks_every_session() {
        let manager = TerminalManager::new();
        let a = vault_session(&manager, Uuid::new_v4()).await;
        let b = vault_session(&manager, Uuid::new_v4()).await;

        manager.recheck_sessions(None).await;

        assert!(a.has_changed().unwrap() && b.has_changed().unwrap());
    }
}
