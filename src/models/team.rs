use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TeamRole {
    pub id: Uuid,
    pub team_id: Uuid,
    pub name: String,
    pub color: Option<String>,
    pub permissions: i64,
    pub is_builtin: bool,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

/// Flattened member response — role_ids aggregated in Rust from a JOIN query.
#[derive(Debug, Serialize)]
pub struct TeamMember {
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub display_name: String,
    pub public_key: String,
    pub invited_by_display_name: Option<String>,
    pub joined_at: DateTime<Utc>,
    pub role_ids: Vec<Uuid>,
}
