use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum SyncEvent {
    /// Another device pushed a blob for this user.
    BlobPushed { user_id: Uuid, device_id: String },
    /// The user's team membership changed (added to or removed from a team).
    MembershipChanged { user_id: Uuid },
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
        let _ = self.0.tx.send(SyncEvent::BlobPushed { user_id, device_id: pusher_device_id });
    }

    pub fn notify_membership_changed(&self, user_id: Uuid) {
        let _ = self.0.tx.send(SyncEvent::MembershipChanged { user_id });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.0.tx.subscribe()
    }
}
