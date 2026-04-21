use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SyncBlob {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: String,
    pub blob: Vec<u8>,
    pub metadata: serde_json::Value,
    pub size_bytes: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
