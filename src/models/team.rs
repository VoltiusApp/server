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
pub struct TeamMember {
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub invited_by: Option<Uuid>,
    pub joined_at: DateTime<Utc>,
    pub email: String,
    pub public_key: String,
    pub custom_role_id: Option<Uuid>,
    pub custom_role_name: Option<String>,
    pub custom_role_permissions: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CustomRole {
    pub id: Uuid,
    pub team_id: Uuid,
    pub name: String,
    pub permissions: i64,
    pub created_at: DateTime<Utc>,
}
