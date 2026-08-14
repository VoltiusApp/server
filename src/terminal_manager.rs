use std::{collections::{HashMap, VecDeque}, sync::Arc};
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

pub const BROADCAST_CAPACITY: usize = 512;
/// Maximum number of encrypted output messages kept per session for late-join replay.
pub const OUTPUT_HISTORY_MAX: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub user_id: Uuid,
    pub display_name: String,
}

pub struct SessionState {
    /// Vaults whose members are allowed to join (empty only for invite_link sessions)
    pub vault_ids: Vec<Uuid>,
    /// Role filter — empty means all roles; non-empty means only these roles can join
    pub allowed_roles: Vec<String>,
    /// Invite token — set for invite_link sessions; required to join/get key
    pub invite_token: Option<String>,
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
                invite_token: None,
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
            },
        );
    }
}
