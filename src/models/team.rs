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
    /// ALIAS for pre-0.26 clients. Value is the handle; there is no stored
    /// `display_name`. Delete this field in 0.27, and never repopulate it.
    pub display_name: String,
    pub handle: String,
    pub public_key: String,
    /// The inviter's handle. The field name is the alias, the value is not.
    pub invited_by_display_name: Option<String>,
    pub joined_at: DateTime<Utc>,
    pub role_ids: Vec<Uuid>,
}
