use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum SyncEvent {
    /// Another device pushed a blob for this user.
    BlobPushed { user_id: Uuid, device_id: String },
    /// The user's team membership changed (added to or removed from a team).
    MembershipChanged { user_id: Uuid },
    /// A teammate's online/offline status changed. `recipient` is who should receive it.
    PresenceChanged {
        recipient: Uuid,
        subject: Uuid,
        online: bool,
    },
}

#[derive(Clone)]
pub struct SyncNotifier(Arc<Inner>);

struct Inner {
    tx: broadcast::Sender<SyncEvent>,
}

impl SyncNotifier {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        Self(Arc::new(Inner { tx }))
    }

    pub fn notify(&self, user_id: Uuid, pusher_device_id: String) {
        let _ = self.0.tx.send(SyncEvent::BlobPushed {
            user_id,
            device_id: pusher_device_id,
        });
    }

    pub fn notify_membership_changed(&self, user_id: Uuid) {
        let _ = self.0.tx.send(SyncEvent::MembershipChanged { user_id });
    }

    pub fn notify_presence_changed(&self, recipient: Uuid, subject: Uuid, online: bool) {
        let _ = self.0.tx.send(SyncEvent::PresenceChanged {
            recipient,
            subject,
            online,
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.0.tx.subscribe()
    }
}

pub fn team_vault_notification_payload(team_id: Uuid) -> String {
    format!("team:{}", team_id)
}

pub async fn notify_team_vault_changed(
    pool: &PgPool,
    notifier: &SyncNotifier,
    team_id: Uuid,
    actor_user_id: Uuid,
) {
    let member_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM team_members WHERE team_id = $1 AND user_id != $2",
    )
    .bind(team_id)
    .bind(actor_user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let payload = team_vault_notification_payload(team_id);
    for member_id in member_ids {
        notifier.notify(member_id, payload.clone());
    }
}
