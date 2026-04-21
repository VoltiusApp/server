use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    pub iat: i64,
    pub kind: String,
    pub tier: String,           // "free" | "pro" | "teams" | "business"
    pub trial_ends_at: Option<i64>, // unix timestamp, null when trial unused or expired
    pub trial_used: bool,
    pub is_admin: bool,
    pub is_banned: bool,
}

impl Claims {
    pub fn is_pro_active(&self) -> bool {
        self.tier != "free"
    }

    pub fn is_teams_active(&self) -> bool {
        matches!(self.tier.as_str(), "teams" | "business")
    }
}

fn secret() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")
        .into_bytes()
}

pub fn create_access_token(
    user_id: Uuid,
    tier: &str,
    trial_ends_at: Option<i64>,
    trial_used: bool,
    is_admin: bool,
    is_banned: bool,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
        kind: "access".to_string(),
        tier: tier.to_string(),
        trial_ends_at,
        trial_used,
        is_admin,
        is_banned,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret()),
    )
}

pub fn create_refresh_token(user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    // Refresh tokens carry no tier — tier is re-read from DB on each refresh.
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp(),
        exp: (now + Duration::days(90)).timestamp(),
        kind: "refresh".to_string(),
        tier: "free".to_string(),
        trial_ends_at: None,
        trial_used: false,
        is_admin: false,
        is_banned: false,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret()),
    )
}

pub fn validate_token(token: &str, expected_kind: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret()),
        &Validation::default(),
    )?;
    if data.claims.kind != expected_kind {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(data.claims)
}
