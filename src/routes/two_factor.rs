use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use tracing::info;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::passkeys::{self, PasskeyInfo};
use crate::routes::auth::{fresh_session, require_auth_key, SessionTokens};
use crate::sync_notifier::SyncNotifier;
use crate::two_factor::{self, db_failure, Context, Refusal, SecondFactorProof, SeedCipher};

/// The master password plus, once the account has a factor, proof of one.
#[derive(Deserialize)]
pub struct StepUpRequest {
    pub auth_key: String,
    #[serde(flatten)]
    pub proof: SecondFactorProof,
}

#[derive(Serialize)]
pub struct SetupResponse {
    pub secret: String,
    pub otpauth_uri: String,
}

async fn totp_enabled(pool: &PgPool, user_id: Uuid) -> Result<bool, Refusal> {
    sqlx::query_scalar("SELECT totp_enabled_at IS NOT NULL FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(db_failure)
}

pub async fn setup(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Json(body): Json<StepUpRequest>,
) -> Result<Json<SetupResponse>, Refusal> {
    let seed = two_factor::generate_seed();
    let sealed = cipher.seal(&seed).ok_or(Refusal::Unavailable)?;
    require_auth_key(&pool, auth.0, &body.auth_key).await?;
    if totp_enabled(&pool, auth.0).await? {
        return Err(Refusal::AlreadyEnabled);
    }
    two_factor::verify_if_enabled(&pool, &cipher, auth.0, &body.proof).await?;

    let email: Option<String> = sqlx::query_scalar(
        "UPDATE users SET totp_secret = $1, totp_last_step = NULL
         WHERE id = $2 AND totp_enabled_at IS NULL RETURNING email",
    )
    .bind(&sealed)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(db_failure)?;
    let email = email.ok_or(Refusal::AlreadyEnabled)?;

    Ok(Json(SetupResponse {
        secret: two_factor::seed_base32(&seed),
        otpauth_uri: two_factor::otpauth_uri(&seed, &email),
    }))
}

/// Recovery codes are only issued with the account's first factor; later ones leave the list empty.
#[derive(Serialize)]
pub struct FactorAdded {
    pub recovery_codes: Vec<String>,
    #[serde(flatten)]
    pub session: SessionTokens,
}

pub async fn conclude_addition(
    pool: &PgPool,
    notifier: &SyncNotifier,
    mut tx: Transaction<'_, Postgres>,
    user_id: Uuid,
    was_enabled: bool,
) -> Result<FactorAdded, Refusal> {
    let recovery_codes =
        two_factor::first_factor_added(&mut tx, user_id, was_enabled).await.map_err(db_failure)?;
    tx.commit().await.map_err(db_failure)?;

    let session = fresh_session(pool, user_id).await?;
    if !was_enabled {
        notifier.notify(user_id, "token_invalidated".to_string());
        info!(user_id = %user_id, "Two-factor authentication enabled");
    }
    Ok(FactorAdded { recovery_codes, session })
}

pub async fn enable(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(proof): Json<SecondFactorProof>,
) -> Result<Json<FactorAdded>, Refusal> {
    if totp_enabled(&pool, auth.0).await? {
        return Err(Refusal::AlreadyEnabled);
    }
    let code_only = SecondFactorProof { code: proof.code, ..Default::default() };
    two_factor::verify_in(&pool, &cipher, auth.0, &code_only, Context::Enrolment).await?;

    let mut tx = pool.begin().await.map_err(db_failure)?;
    let was_enabled = two_factor::lock_enabled(&mut tx, auth.0).await.map_err(db_failure)?;
    let enabled = sqlx::query(
        "UPDATE users SET totp_enabled_at = now()
         WHERE id = $1 AND totp_enabled_at IS NULL AND totp_secret IS NOT NULL",
    )
    .bind(auth.0)
    .execute(&mut *tx)
    .await
    .map_err(db_failure)?;
    if enabled.rows_affected() == 0 {
        return Err(Refusal::AlreadyEnabled);
    }
    conclude_addition(&pool, &notifier, tx, auth.0, was_enabled).await.map(Json)
}

pub enum Factor {
    All,
    Totp,
    Passkey(Uuid),
}

#[derive(Serialize)]
pub struct Removal {
    pub two_factor_enabled: bool,
    #[serde(flatten)]
    pub session: SessionTokens,
}

/// Removing the last factor turns two-factor off, which ends every other session.
pub async fn remove(
    pool: &PgPool,
    cipher: &SeedCipher,
    notifier: &SyncNotifier,
    user_id: Uuid,
    body: &StepUpRequest,
    factor: Factor,
) -> Result<Json<Removal>, Refusal> {
    if !two_factor::is_enabled(pool, user_id).await? {
        return Err(Refusal::NotEnabled);
    }
    require_auth_key(pool, user_id, &body.auth_key).await?;
    two_factor::verify(pool, cipher, user_id, &body.proof).await?;

    let mut tx = pool.begin().await.map_err(db_failure)?;
    let removed = match factor {
        Factor::All => two_factor::remove_all(&mut tx, user_id).await,
        Factor::Totp => two_factor::remove_totp(&mut tx, user_id).await,
        Factor::Passkey(id) => passkeys::remove(&mut tx, user_id, id).await,
    }
    .map_err(db_failure)?;
    if !removed {
        return Err(StatusCode::NOT_FOUND.into());
    }
    let two_factor_enabled = two_factor::settle_after_removal(&mut tx, user_id).await.map_err(db_failure)?;
    tx.commit().await.map_err(db_failure)?;

    let session = fresh_session(pool, user_id).await?;
    if !two_factor_enabled {
        notifier.notify(user_id, "token_invalidated".to_string());
        info!(user_id = %user_id, "Two-factor authentication disabled");
    }
    Ok(Json(Removal { two_factor_enabled, session }))
}

pub async fn disable(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(body): Json<StepUpRequest>,
) -> Result<Json<Removal>, Refusal> {
    remove(&pool, &cipher, &notifier, auth.0, &body, Factor::All).await
}

pub async fn remove_totp(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(body): Json<StepUpRequest>,
) -> Result<Json<Removal>, Refusal> {
    remove(&pool, &cipher, &notifier, auth.0, &body, Factor::Totp).await
}

#[derive(Serialize)]
pub struct Factors {
    pub totp: bool,
    pub passkeys: Vec<PasskeyInfo>,
    pub recovery_codes_left: i64,
}

pub async fn factors(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Factors>, Refusal> {
    let recovery_codes_left =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL")
            .bind(auth.0)
            .fetch_one(&pool)
            .await
            .map_err(db_failure)?;
    Ok(Json(Factors {
        totp: totp_enabled(&pool, auth.0).await?,
        passkeys: passkeys::list(&pool, auth.0).await.map_err(db_failure)?,
        recovery_codes_left,
    }))
}

#[derive(Serialize)]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

pub async fn regenerate_recovery_codes(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Json(proof): Json<SecondFactorProof>,
) -> Result<Json<RecoveryCodesResponse>, Refusal> {
    if !two_factor::is_enabled(&pool, auth.0).await? {
        return Err(Refusal::NotEnabled);
    }
    two_factor::verify(&pool, &cipher, auth.0, &proof).await?;

    let mut tx = pool.begin().await.map_err(db_failure)?;
    let recovery_codes = two_factor::replace_recovery_codes(&mut tx, auth.0).await.map_err(db_failure)?;
    tx.commit().await.map_err(db_failure)?;
    info!(user_id = %auth.0, "Recovery codes regenerated");

    Ok(Json(RecoveryCodesResponse { recovery_codes }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::jwt::{create_refresh_token, validate_token};
    use crate::routes::auth::{
        login, login_second_factor, refresh, update_password, LoginOutcome, LoginRequest, RefreshRequest,
        SecondFactorChallenge, SecondFactorLoginRequest, UpdatePasswordRequest,
    };
    use crate::passkeys::Passkeys;
    use crate::test_pool_or_skip;
    use crate::test_support::{env_lock, seed_user_with_credentials, EnvLockGuard};
    use axum::http::StatusCode;
    use uuid::Uuid;

    pub(crate) const AUTH_KEY: &str = "auth-key-secret";

    pub(crate) struct Enrolled {
        pub uid: Uuid,
        pub account_id: Uuid,
        pub seed: Vec<u8>,
        pub recovery_codes: Vec<String>,
        pub session: SessionTokens,
    }

    pub(crate) fn jwt_env() -> EnvLockGuard {
        let guard = env_lock();
        std::env::set_var("JWT_SECRET", "ci-test-secret");
        EnvLockGuard(guard)
    }

    pub(crate) fn code(value: &str) -> SecondFactorProof {
        SecondFactorProof { code: Some(value.to_string()), ..Default::default() }
    }

    pub(crate) fn recovery(value: &str) -> SecondFactorProof {
        SecondFactorProof { recovery_code: Some(value.to_string()), ..Default::default() }
    }

    pub(crate) fn step_up_request(auth_key: &str, proof: SecondFactorProof) -> StepUpRequest {
        StepUpRequest { auth_key: auth_key.to_string(), proof }
    }

    /// A code the server has not seen yet: replay protection would refuse the one used a moment ago.
    pub(crate) async fn unused_code(pool: &PgPool, user: &Enrolled) -> String {
        sqlx::query("UPDATE users SET totp_last_step = NULL WHERE id = $1")
            .bind(user.uid)
            .execute(pool)
            .await
            .unwrap();
        two_factor::totp_at(&user.seed, two_factor::current_step())
    }

    pub(crate) async fn begin_setup_with(
        pool: &PgPool,
        cipher: &SeedCipher,
        uid: Uuid,
        proof: SecondFactorProof,
    ) -> Result<Vec<u8>, Refusal> {
        let Json(pending) = setup(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(cipher.clone()),
            Json(step_up_request(AUTH_KEY, proof)),
        )
        .await?;
        assert!(pending.otpauth_uri.contains(&pending.secret));
        Ok(data_encoding::BASE32_NOPAD.decode(pending.secret.as_bytes()).unwrap())
    }

    async fn begin_setup(pool: &PgPool, cipher: &SeedCipher, uid: Uuid) -> Result<Vec<u8>, Refusal> {
        begin_setup_with(pool, cipher, uid, SecondFactorProof::default()).await
    }

    pub(crate) async fn confirm(pool: &PgPool, uid: Uuid, proof: SecondFactorProof) -> Result<FactorAdded, Refusal> {
        enable(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(SeedCipher::for_tests()),
            Extension(SyncNotifier::new()),
            Json(proof),
        )
        .await
        .map(|Json(r)| r)
    }

    pub(crate) async fn enrol(pool: &PgPool) -> Enrolled {
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(pool, account_id, AUTH_KEY).await;
        let seed = begin_setup(pool, &SeedCipher::for_tests(), uid).await.expect("setup ok");
        let enabled = confirm(pool, uid, code(&two_factor::totp_at(&seed, two_factor::current_step())))
            .await
            .expect("enable ok");
        Enrolled { uid, account_id, seed, recovery_codes: enabled.recovery_codes, session: enabled.session }
    }

    pub(crate) async fn challenge_with(pool: &PgPool, cipher: SeedCipher, account_id: Uuid) -> SecondFactorChallenge {
        let outcome = login(
            State(pool.clone()),
            Extension(cipher),
            Extension(Passkeys::for_tests()),
            Json(LoginRequest { account_id, auth_key: AUTH_KEY.to_string() }),
        )
        .await
        .expect("password accepted");
        match outcome {
            LoginOutcome::SecondFactorRequired(challenge) => challenge,
            LoginOutcome::Session(_) => panic!("a session was issued without the second factor"),
        }
    }

    async fn finish_with(
        pool: &PgPool,
        cipher: SeedCipher,
        pending_token: &str,
        proof: SecondFactorProof,
    ) -> Result<crate::routes::auth::AuthResponse, Refusal> {
        login_second_factor(
            State(pool.clone()),
            Extension(cipher),
            Json(SecondFactorLoginRequest { pending_token: pending_token.to_string(), proof }),
        )
        .await
        .map(|Json(r)| r)
    }

    pub(crate) async fn finish(
        pool: &PgPool,
        pending_token: &str,
        proof: SecondFactorProof,
    ) -> Result<crate::routes::auth::AuthResponse, Refusal> {
        finish_with(pool, SeedCipher::for_tests(), pending_token, proof).await
    }

    pub(crate) async fn refreshes(pool: &PgPool, refresh_token: &str) -> bool {
        refresh(State(pool.clone()), Json(RefreshRequest { refresh_token: refresh_token.to_string() }))
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn sign_in_stops_at_the_password_until_a_code_arrives() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;

        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        assert_eq!(challenge.error, "TWO_FACTOR_REQUIRED");
        assert_eq!(challenge.methods, ["totp", "recovery"]);
        let body = serde_json::to_value(&challenge).unwrap();
        assert!(body.get("jwt_token").is_none() && body.get("wrapped_user_secrets").is_none());
        assert!(validate_token(&challenge.pending_token, "access").is_err());
        assert!(!refreshes(&pool, &challenge.pending_token).await);

        assert_eq!(finish(&pool, &challenge.pending_token, code("000000")).await.err(), Some(Refusal::Invalid));
        assert_eq!(
            finish(&pool, &challenge.pending_token, SecondFactorProof::default()).await.err(),
            Some(Refusal::Required)
        );

        let good = unused_code(&pool, &user).await;
        let session = finish(&pool, &challenge.pending_token, code(&good)).await.expect("code accepted");
        assert_eq!(session.user_id, user.uid);
        assert!(refreshes(&pool, &session.refresh_token).await);

        assert_eq!(
            finish(&pool, &challenge.pending_token, code(&good)).await.err(),
            Some(Refusal::Invalid),
            "a code must not open a second session"
        );
    }

    #[tokio::test]
    async fn a_recovery_code_signs_in_once() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        let typed = user.recovery_codes[0].replace('-', " ").to_uppercase();

        assert!(finish(&pool, &challenge.pending_token, recovery(&typed)).await.is_ok());
        assert_eq!(
            finish(&pool, &challenge.pending_token, recovery(&user.recovery_codes[0])).await.err(),
            Some(Refusal::Invalid)
        );
        assert!(finish(&pool, &challenge.pending_token, recovery(&user.recovery_codes[1])).await.is_ok());
    }

    #[tokio::test]
    async fn five_wrong_codes_lock_the_second_step() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;

        for _ in 0..5 {
            assert_eq!(
                finish(&pool, &challenge.pending_token, code("000000")).await.err(),
                Some(Refusal::Invalid)
            );
        }
        let good = unused_code(&pool, &user).await;
        assert_eq!(finish(&pool, &challenge.pending_token, code(&good)).await.err(), Some(Refusal::Locked));
        assert_eq!(
            finish(&pool, &challenge.pending_token, recovery(&user.recovery_codes[0])).await.err(),
            Some(Refusal::Locked)
        );

        sqlx::query("UPDATE users SET totp_locked_until = now() - interval '1 second' WHERE id = $1")
            .bind(user.uid)
            .execute(&pool)
            .await
            .unwrap();
        assert!(finish(&pool, &challenge.pending_token, code(&good)).await.is_ok());
    }

    #[tokio::test]
    async fn enabling_needs_the_first_code_and_ends_earlier_sessions() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let uid = seed_user_with_credentials(&pool, Uuid::new_v4(), AUTH_KEY).await;
        let before = create_refresh_token(uid, 0).unwrap();
        let seed = begin_setup(&pool, &SeedCipher::for_tests(), uid).await.expect("setup ok");

        assert_eq!(confirm(&pool, uid, code("000000")).await.err(), Some(Refusal::Invalid));
        assert_eq!(
            confirm(&pool, uid, recovery("anything")).await.err(),
            Some(Refusal::Required),
            "only a code from the new seed proves the authenticator works"
        );
        assert!(refreshes(&pool, &before).await, "a failed attempt changes nothing");

        let enabled = confirm(&pool, uid, code(&two_factor::totp_at(&seed, two_factor::current_step())))
            .await
            .expect("enable ok");
        assert_eq!(enabled.recovery_codes.len(), two_factor::RECOVERY_CODE_COUNT);
        assert!(!refreshes(&pool, &before).await);
        assert!(refreshes(&pool, &enabled.session.refresh_token).await);

        assert_eq!(
            begin_setup(&pool, &SeedCipher::for_tests(), uid).await.err(),
            Some(Refusal::AlreadyEnabled)
        );
        assert_eq!(confirm(&pool, uid, code("000000")).await.err(), Some(Refusal::AlreadyEnabled));
    }

    #[tokio::test]
    async fn setup_needs_the_password_and_the_seed_key() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let uid = seed_user_with_credentials(&pool, Uuid::new_v4(), "another-key").await;

        assert_eq!(
            begin_setup(&pool, &SeedCipher::for_tests(), uid).await.err(),
            Some(Refusal::Status(StatusCode::UNAUTHORIZED))
        );
        assert_eq!(begin_setup(&pool, &SeedCipher::absent(), uid).await.err(), Some(Refusal::Unavailable));
    }

    #[tokio::test]
    async fn disabling_needs_password_and_code_then_sign_in_is_plain_again() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let turn_off = |auth_key: &'static str, proof: SecondFactorProof| {
            disable(
                State(pool.clone()),
                Extension(AuthUser(user.uid)),
                Extension(SeedCipher::for_tests()),
                Extension(SyncNotifier::new()),
                Json(step_up_request(auth_key, proof)),
            )
        };

        let good = unused_code(&pool, &user).await;
        assert_eq!(
            turn_off("wrong-key", code(&good)).await.err(),
            Some(Refusal::Status(StatusCode::UNAUTHORIZED))
        );
        assert_eq!(turn_off(AUTH_KEY, code("000000")).await.err(), Some(Refusal::Invalid));

        let Json(off) = turn_off(AUTH_KEY, code(&good)).await.expect("disable ok");
        assert!(!off.two_factor_enabled);
        assert!(!refreshes(&pool, &user.session.refresh_token).await);
        assert!(refreshes(&pool, &off.session.refresh_token).await);
        assert_eq!(turn_off(AUTH_KEY, code(&good)).await.err(), Some(Refusal::NotEnabled));

        let outcome = login(
            State(pool.clone()),
            Extension(SeedCipher::for_tests()),
            Extension(Passkeys::for_tests()),
            Json(LoginRequest { account_id: user.account_id, auth_key: AUTH_KEY.to_string() }),
        )
        .await
        .expect("login ok");
        assert!(matches!(outcome, LoginOutcome::Session(_)));
        let leftover: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = $1")
            .bind(user.uid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(leftover, 0);
    }

    #[tokio::test]
    async fn regenerating_recovery_codes_retires_the_old_set() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let regenerate = |proof: SecondFactorProof| {
            regenerate_recovery_codes(
                State(pool.clone()),
                Extension(AuthUser(user.uid)),
                Extension(SeedCipher::for_tests()),
                Json(proof),
            )
        };

        assert_eq!(regenerate(code("000000")).await.err(), Some(Refusal::Invalid));
        let good = unused_code(&pool, &user).await;
        let Json(fresh) = regenerate(code(&good)).await.expect("regenerate ok");

        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        assert_eq!(
            finish(&pool, &challenge.pending_token, recovery(&user.recovery_codes[0])).await.err(),
            Some(Refusal::Invalid)
        );
        assert!(finish(&pool, &challenge.pending_token, recovery(&fresh.recovery_codes[0])).await.is_ok());
    }

    #[tokio::test]
    async fn a_server_without_the_seed_key_refuses_codes_but_never_skips_the_step() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;

        let challenge = challenge_with(&pool, SeedCipher::absent(), user.account_id).await;
        assert_eq!(challenge.methods, ["recovery"]);

        let good = unused_code(&pool, &user).await;
        assert_eq!(
            finish_with(&pool, SeedCipher::absent(), &challenge.pending_token, code(&good)).await.err(),
            Some(Refusal::Unavailable)
        );
        assert!(finish_with(
            &pool,
            SeedCipher::absent(),
            &challenge.pending_token,
            recovery(&user.recovery_codes[0])
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn a_pending_token_dies_with_the_token_version() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;

        sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1")
            .bind(user.uid)
            .execute(&pool)
            .await
            .unwrap();

        let good = unused_code(&pool, &user).await;
        assert_eq!(
            finish(&pool, &challenge.pending_token, code(&good)).await.err(),
            Some(Refusal::Status(StatusCode::UNAUTHORIZED))
        );
        assert_eq!(
            finish(&pool, "not-a-token", code(&good)).await.err(),
            Some(Refusal::Status(StatusCode::UNAUTHORIZED))
        );
    }

    #[tokio::test]
    async fn changing_the_password_takes_a_code_once_two_factor_is_on() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let change = |proof: SecondFactorProof| {
            update_password(
                State(pool.clone()),
                Extension(AuthUser(user.uid)),
                Extension(SyncNotifier::new()),
                Extension(SeedCipher::for_tests()),
                Json(UpdatePasswordRequest {
                    old_auth_key: AUTH_KEY.to_string(),
                    new_auth_key: "new-auth-key".to_string(),
                    new_wrapped_user_secrets: "wrapped".to_string(),
                    proof,
                }),
            )
        };

        assert_eq!(change(SecondFactorProof::default()).await.err(), Some(Refusal::Required));
        let good = unused_code(&pool, &user).await;
        assert!(change(code(&good)).await.is_ok());
    }

    #[tokio::test]
    async fn an_admin_clear_lets_the_password_alone_sign_in_and_is_audited() {
        use crate::auth::AdminEmail;
        use axum::extract::Path;
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let clear = || {
            crate::routes::admin::clear_two_factor(
                State(pool.clone()),
                Extension(AdminEmail("admin@test.local".to_string())),
                Extension(SyncNotifier::new()),
                Path(user.uid),
            )
        };

        assert_eq!(clear().await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(clear().await, Err(StatusCode::NOT_FOUND));

        assert!(!refreshes(&pool, &user.session.refresh_token).await);
        let outcome = login(
            State(pool.clone()),
            Extension(SeedCipher::for_tests()),
            Extension(Passkeys::for_tests()),
            Json(LoginRequest { account_id: user.account_id, auth_key: AUTH_KEY.to_string() }),
        )
        .await
        .expect("login ok");
        assert!(matches!(outcome, LoginOutcome::Session(_)));
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_audit_log WHERE target_id = $1 AND action = 'clear_two_factor'",
        )
        .bind(user.uid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited, 1);
    }
}
