use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatTeamClaim {
    pub id: Uuid,
    pub name: String,
    pub trial: bool,
}

pub struct PlanClaims {
    pub tier: String,
    pub billing_tier: String,
    pub seat_team: Option<SeatTeamClaim>,
}

impl PlanClaims {
    #[cfg(test)]
    pub fn own(tier: &str) -> Self {
        Self { tier: tier.to_string(), billing_tier: tier.to_string(), seat_team: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    pub iat: i64,
    pub kind: String,
    pub tier: String,               // "free" | "pro" | "teams" | "business"
    pub trial_ends_at: Option<i64>, // unix timestamp, null when trial unused or expired
    pub trial_used: bool,
    pub is_admin: bool,
    pub is_banned: bool,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub ver: i32,
    /// Tells apart two pending sign-ins issued to one account within the same second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<Uuid>,
    /// The user's own plan; `tier` may be raised by a team seat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_team: Option<SeatTeamClaim>,
}

impl Claims {
    pub fn billing_tier(&self) -> &str {
        self.billing_tier.as_deref().unwrap_or(&self.tier)
    }

    pub fn owns_teams_plan(&self) -> bool {
        matches!(self.billing_tier(), "teams" | "business")
    }

    pub fn is_pro_active(&self) -> bool {
        self.tier != "free"
    }
}

fn secret() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")
        .into_bytes()
}

pub fn create_access_token(
    user_id: Uuid,
    plan: PlanClaims,
    trial_ends_at: Option<i64>,
    trial_used: bool,
    is_admin: bool,
    is_banned: bool,
    email_verified: bool,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
        kind: "access".to_string(),
        tier: plan.tier,
        trial_ends_at,
        trial_used,
        is_admin,
        is_banned,
        email_verified,
        ver: 0,
        jti: None,
        billing_tier: Some(plan.billing_tier),
        seat_team: plan.seat_team,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret()),
    )
}

pub const PENDING_SECOND_FACTOR: &str = "2fa_pending";

// Refresh and pending tokens carry no tier: it is re-read from the database when they are used.
fn bare_token(
    user_id: Uuid,
    kind: &str,
    lifetime: Duration,
    token_version: i32,
    jti: Option<Uuid>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp(),
        exp: (now + lifetime).timestamp(),
        kind: kind.to_string(),
        tier: "free".to_string(),
        trial_ends_at: None,
        trial_used: false,
        is_admin: false,
        is_banned: false,
        email_verified: false,
        ver: token_version,
        jti,
        billing_tier: None,
        seat_team: None,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret()),
    )
}

pub fn create_refresh_token(
    user_id: Uuid,
    token_version: i32,
) -> Result<String, jsonwebtoken::errors::Error> {
    bare_token(user_id, "refresh", Duration::days(90), token_version, None)
}

pub fn create_pending_token(
    user_id: Uuid,
    token_version: i32,
) -> Result<String, jsonwebtoken::errors::Error> {
    bare_token(user_id, PENDING_SECOND_FACTOR, Duration::minutes(5), token_version, Some(Uuid::new_v4()))
}

pub fn validate_token(
    token: &str,
    expected_kind: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[derive(Serialize)]
    struct LegacyClaims {
        sub: Uuid,
        exp: i64,
        iat: i64,
        kind: String,
        tier: String,
        trial_ends_at: Option<i64>,
        trial_used: bool,
        is_admin: bool,
        is_banned: bool,
    }

    pub(crate) fn legacy_token(user_id: Uuid, kind: &str, secret: &str) -> String {
        let now = Utc::now();
        encode(
            &Header::default(),
            &LegacyClaims {
                sub: user_id,
                iat: now.timestamp(),
                exp: (now + Duration::hours(1)).timestamp(),
                kind: kind.to_string(),
                tier: "pro".to_string(),
                trial_ends_at: None,
                trial_used: false,
                is_admin: false,
                is_banned: false,
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn access_token_includes_email_verified_claim() {
        // Serialize JWT_SECRET mutation against other env-touching tests (e.g. the
        // auth middleware tests set a different secret); the lock has no async here.
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");
        let user_id = Uuid::new_v4();

        let token = create_access_token(user_id, PlanClaims::own("pro"), None, false, false, false, true).unwrap();
        let claims = validate_token(&token, "access").unwrap();

        assert!(claims.email_verified);
        assert_eq!(claims.sub, user_id);
    }

    #[test]
    fn legacy_token_decodes_with_defaults_for_later_claims() {
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");
        let user_id = Uuid::new_v4();

        let claims = validate_token(&legacy_token(user_id, "access", "test-secret"), "access").unwrap();

        assert!(!claims.email_verified);
        assert_eq!(claims.ver, 0);
        assert_eq!(claims.sub, user_id);
    }

    #[test]
    fn a_pending_token_passes_for_nothing_else() {
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");

        let token = create_pending_token(Uuid::new_v4(), 3).unwrap();

        assert_eq!(validate_token(&token, PENDING_SECOND_FACTOR).unwrap().ver, 3);
        assert!(validate_token(&token, "access").is_err());
        assert!(validate_token(&token, "refresh").is_err());
    }

    #[test]
    fn two_pending_tokens_for_one_account_never_match() {
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");
        let user = Uuid::new_v4();

        assert_ne!(create_pending_token(user, 3).unwrap(), create_pending_token(user, 3).unwrap());
    }

    #[test]
    fn refresh_token_carries_the_token_version() {
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");

        let token = create_refresh_token(Uuid::new_v4(), 7).unwrap();

        assert_eq!(validate_token(&token, "refresh").unwrap().ver, 7);
    }

    #[test]
    fn old_token_without_seat_claims_falls_back_to_tier() {
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");
        let claims = validate_token(&legacy_token(Uuid::new_v4(), "access", "test-secret"), "access").unwrap();
        assert_eq!(claims.seat_team, None);
        assert_eq!(claims.billing_tier(), "pro");
    }

    #[test]
    fn seat_claims_round_trip() {
        let _guard = crate::test_support::env_lock();
        std::env::set_var("JWT_SECRET", "test-secret");
        let seat = SeatTeamClaim { id: Uuid::new_v4(), name: "Acme".into(), trial: true };
        let token =
            create_access_token(
                Uuid::new_v4(),
                PlanClaims { tier: "teams".into(), billing_tier: "free".into(), seat_team: Some(seat.clone()) },
                None,
                false,
                false,
                false,
                true,
            )
            .unwrap();
        let claims = validate_token(&token, "access").unwrap();
        assert_eq!(claims.tier, "teams");
        assert_eq!(claims.billing_tier(), "free");
        assert_eq!(claims.seat_team, Some(seat));
        assert!(!claims.owns_teams_plan());
    }
}
