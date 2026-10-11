use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::passkeys::{self, Begun, Ceremony, Finished, Handle, PasskeyInfo, Passkeys, ReturnTo};
use crate::routes::auth::{pending_sign_in, require_auth_key};
use crate::routes::two_factor::{conclude_addition, remove, Factor, FactorAdded, Removal, StepUpRequest};
use crate::sync_notifier::SyncNotifier;
use crate::two_factor::{self, db_failure, Refusal, SeedCipher};

#[derive(Deserialize)]
pub struct SignInRequest {
    pub pending_token: String,
    pub return_to: ReturnTo,
}

pub async fn sign_in(
    State(pool): State<PgPool>,
    Extension(passkeys): Extension<Passkeys>,
    Json(body): Json<SignInRequest>,
) -> Result<Json<Handle>, Refusal> {
    let user_id = pending_sign_in(&pool, &body.pending_token).await?.user_id;
    let ceremony = Ceremony::SignIn { pending_token: body.pending_token };
    passkeys.open(&pool, user_id, ceremony, body.return_to).await.map(Json)
}

#[derive(Deserialize)]
pub struct StepUpHandleRequest {
    pub return_to: ReturnTo,
}

pub async fn step_up(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(passkeys): Extension<Passkeys>,
    Json(body): Json<StepUpHandleRequest>,
) -> Result<Json<Handle>, Refusal> {
    passkeys.open(&pool, auth.0, Ceremony::StepUp, body.return_to).await.map(Json)
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    #[serde(flatten)]
    pub step_up: StepUpRequest,
    #[serde(default)]
    pub name: String,
    pub return_to: ReturnTo,
}

pub async fn register(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Extension(passkeys): Extension<Passkeys>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<Handle>, Refusal> {
    if !passkeys.available() {
        return Err(Refusal::Unavailable);
    }
    require_auth_key(&pool, auth.0, &body.step_up.auth_key).await?;
    two_factor::verify_if_enabled(&pool, &cipher, auth.0, &body.step_up.proof).await?;
    passkeys.open(&pool, auth.0, Ceremony::Register { name: body.name }, body.return_to).await.map(Json)
}

#[derive(Deserialize)]
pub struct BeginRequest {
    pub handle: String,
}

pub async fn begin(
    State(pool): State<PgPool>,
    Extension(passkeys): Extension<Passkeys>,
    Json(body): Json<BeginRequest>,
) -> Result<Json<Begun>, Refusal> {
    passkeys.begin(&pool, &body.handle).await.map(Json)
}

#[derive(Deserialize)]
pub struct FinishRequest {
    pub handle: String,
    pub response: Value,
}

pub async fn finish(
    State(pool): State<PgPool>,
    Extension(passkeys): Extension<Passkeys>,
    Json(body): Json<FinishRequest>,
) -> Result<Json<Finished>, Refusal> {
    passkeys.finish(&pool, &body.handle, body.response).await.map(Json)
}

#[derive(Deserialize)]
pub struct ActivateRequest {
    pub passkey_code: String,
}

#[derive(Serialize)]
pub struct Activated {
    pub passkey: PasskeyInfo,
    #[serde(flatten)]
    pub added: FactorAdded,
}

pub async fn activate(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(body): Json<ActivateRequest>,
) -> Result<Json<Activated>, Refusal> {
    let mut tx = pool.begin().await.map_err(db_failure)?;
    let was_enabled = two_factor::lock_enabled(&mut tx, auth.0).await.map_err(db_failure)?;
    let passkey = passkeys::activate(&mut tx, auth.0, &body.passkey_code)
        .await
        .map_err(db_failure)?
        .ok_or(Refusal::Invalid)?;
    let added = conclude_addition(&pool, &notifier, tx, auth.0, was_enabled).await?;
    Ok(Json(Activated { passkey, added }))
}

pub async fn remove_passkey(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(cipher): Extension<SeedCipher>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(passkey_id): Path<Uuid>,
    Json(body): Json<StepUpRequest>,
) -> Result<Json<Removal>, Refusal> {
    remove(&pool, &cipher, &notifier, auth.0, &body, Factor::Passkey(passkey_id)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::create_refresh_token;
    use crate::passkeys::Purpose;
    use crate::routes::auth::{login, LoginOutcome, LoginRequest};
    use crate::routes::two_factor::tests::{
        begin_setup_with, challenge_with, code, confirm, enrol, finish as sign_in_with, jwt_env, recovery, refreshes,
        step_up_request, unused_code, AUTH_KEY,
    };
    use crate::routes::two_factor::{factors, regenerate_recovery_codes, remove_totp};
    use crate::test_pool_or_skip;
    use crate::test_support::seed_user_with_credentials;
    use crate::two_factor::SecondFactorProof;
    use axum::http::StatusCode;
    use url::Url;
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    fn desktop() -> ReturnTo {
        ReturnTo::Loopback { port: 49152, state: "n0nce".to_string() }
    }

    fn phone() -> ReturnTo {
        ReturnTo::App { state: String::new() }
    }

    struct Device(WebauthnAuthenticator<SoftPasskey>);

    impl Device {
        fn new() -> Self {
            Self(WebauthnAuthenticator::new(SoftPasskey::new(true)))
        }

        async fn answer(&mut self, pool: &PgPool, handle: &Handle) -> Result<Value, Refusal> {
            let request = BeginRequest { handle: handle.handle.clone() };
            let Json(begun) = begin(State(pool.clone()), Extension(Passkeys::for_tests()), Json(request)).await?;
            let origin = Url::parse(Passkeys::TEST_ORIGIN).unwrap();
            Ok(if begun.purpose == Purpose::Register {
                let options: CreationChallengeResponse = serde_json::from_value(begun.options).unwrap();
                serde_json::to_value(self.0.do_registration(origin, options).expect("registration")).unwrap()
            } else {
                let options: RequestChallengeResponse = serde_json::from_value(begun.options).unwrap();
                serde_json::to_value(self.0.do_authentication(origin, options).expect("assertion")).unwrap()
            })
        }

        /// The browser's half of a ceremony; returns the code the client gets back.
        async fn complete(&mut self, pool: &PgPool, handle: &Handle) -> Result<String, Refusal> {
            let response = self.answer(pool, handle).await?;
            let done = submit(pool, handle, response).await?;
            Ok(done.code.unwrap_or_else(|| {
                let redirect = done.redirect.expect("a redirect");
                let query = redirect.split_once("c=").expect("a code").1;
                query.split('&').next().unwrap().to_string()
            }))
        }
    }

    async fn submit(pool: &PgPool, handle: &Handle, response: Value) -> Result<Finished, Refusal> {
        let request = FinishRequest { handle: handle.handle.clone(), response };
        finish(State(pool.clone()), Extension(Passkeys::for_tests()), Json(request)).await.map(|Json(done)| done)
    }

    fn passkey(code: &str) -> SecondFactorProof {
        SecondFactorProof { passkey_code: Some(code.to_string()), ..Default::default() }
    }

    async fn open_registration(
        pool: &PgPool,
        passkeys: Passkeys,
        uid: Uuid,
        proof: SecondFactorProof,
    ) -> Result<Handle, Refusal> {
        register(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(SeedCipher::for_tests()),
            Extension(passkeys),
            Json(RegisterRequest {
                step_up: step_up_request(AUTH_KEY, proof),
                name: " Laptop ".to_string(),
                return_to: desktop(),
            }),
        )
        .await
        .map(|Json(handle)| handle)
    }

    async fn add_passkey(
        pool: &PgPool,
        uid: Uuid,
        device: &mut Device,
        proof: SecondFactorProof,
    ) -> Result<Activated, Refusal> {
        let handle = open_registration(pool, Passkeys::for_tests(), uid, proof).await?;
        let passkey_code = device.complete(pool, &handle).await?;
        activate(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(SyncNotifier::new()),
            Json(ActivateRequest { passkey_code }),
        )
        .await
        .map(|Json(activated)| activated)
    }

    async fn open_sign_in(pool: &PgPool, pending_token: &str, return_to: ReturnTo) -> Result<Handle, Refusal> {
        let request = SignInRequest { pending_token: pending_token.to_string(), return_to };
        sign_in(State(pool.clone()), Extension(Passkeys::for_tests()), Json(request)).await.map(|Json(handle)| handle)
    }

    async fn step_up_code(pool: &PgPool, uid: Uuid, device: &mut Device) -> String {
        let Json(handle) = step_up(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(Passkeys::for_tests()),
            Json(StepUpHandleRequest { return_to: phone() }),
        )
        .await
        .expect("handle");
        device.complete(pool, &handle).await.expect("assertion")
    }

    struct Holder {
        uid: Uuid,
        account_id: Uuid,
        device: Device,
        added: Activated,
    }

    async fn with_passkey(pool: &PgPool) -> Holder {
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(pool, account_id, AUTH_KEY).await;
        let mut device = Device::new();
        let added = add_passkey(pool, uid, &mut device, SecondFactorProof::default()).await.expect("first passkey");
        Holder { uid, account_id, device, added }
    }

    async fn signs_in_with_the_password_alone(pool: &PgPool, account_id: Uuid) -> bool {
        let outcome = login(
            State(pool.clone()),
            Extension(SeedCipher::for_tests()),
            Extension(Passkeys::for_tests()),
            Json(LoginRequest { account_id, auth_key: AUTH_KEY.to_string() }),
        )
        .await
        .expect("password accepted");
        matches!(outcome, LoginOutcome::Session(_))
    }

    async fn remove_one(pool: &PgPool, uid: Uuid, passkey_id: Uuid, proof: SecondFactorProof) -> Result<Removal, Refusal> {
        remove_passkey(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(SeedCipher::for_tests()),
            Extension(SyncNotifier::new()),
            Path(passkey_id),
            Json(step_up_request(AUTH_KEY, proof)),
        )
        .await
        .map(|Json(removal)| removal)
    }

    #[tokio::test]
    async fn a_first_passkey_turns_two_factor_on() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, AUTH_KEY).await;
        let before = create_refresh_token(uid, 0).unwrap();
        let mut device = Device::new();

        let handle = open_registration(&pool, Passkeys::for_tests(), uid, SecondFactorProof::default())
            .await
            .expect("the password is enough without a factor");
        assert!(handle.url.starts_with("https://app.voltius.test/2fa/passkey#h="));
        let passkey_code = device.complete(&pool, &handle).await.expect("registration");
        assert!(signs_in_with_the_password_alone(&pool, account_id).await, "nothing is on until the client confirms");
        assert!(refreshes(&pool, &before).await);

        let activate_with = |passkey_code: String| {
            activate(
                State(pool.clone()),
                Extension(AuthUser(uid)),
                Extension(SyncNotifier::new()),
                Json(ActivateRequest { passkey_code }),
            )
        };
        assert_eq!(activate_with("not-the-code".to_string()).await.err(), Some(Refusal::Invalid));
        let Json(added) = activate_with(passkey_code.clone()).await.expect("activation");
        assert_eq!(added.passkey.name, "Laptop");
        assert_eq!(added.added.recovery_codes.len(), two_factor::RECOVERY_CODE_COUNT);
        assert!(!refreshes(&pool, &before).await);
        assert!(refreshes(&pool, &added.added.session.refresh_token).await);
        assert_eq!(activate_with(passkey_code).await.err(), Some(Refusal::Invalid), "a code registers one passkey");

        let Json(held) = factors(State(pool.clone()), Extension(AuthUser(uid))).await.unwrap();
        assert!(!held.totp);
        assert_eq!(held.passkeys.len(), 1);
        assert_eq!(held.recovery_codes_left, two_factor::RECOVERY_CODE_COUNT as i64);

        let challenge = challenge_with(&pool, SeedCipher::for_tests(), account_id).await;
        assert_eq!(challenge.methods, ["passkey", "recovery"]);
        let recovery_code = &added.added.recovery_codes[0];
        assert!(sign_in_with(&pool, &challenge.pending_token, recovery(recovery_code)).await.is_ok());
    }

    #[tokio::test]
    async fn a_passkey_code_fits_only_the_sign_in_it_was_opened_for() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let mut user = with_passkey(&pool).await;
        let mine = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        let theirs = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;

        let handle = open_sign_in(&pool, &mine.pending_token, desktop()).await.expect("handle");
        let response = user.device.answer(&pool, &handle).await.expect("assertion");
        let done = submit(&pool, &handle, response).await.expect("finish");
        let redirect = done.redirect.expect("a desktop sign-in is sent to the loopback listener");
        let passkey_code = redirect
            .strip_prefix("http://127.0.0.1:49152/passkey?c=")
            .and_then(|query| query.strip_suffix("&s=n0nce"))
            .expect("the loopback address, the code, then the client's state")
            .to_string();
        assert_eq!(done.code, None);

        assert_eq!(
            sign_in_with(&pool, &theirs.pending_token, passkey(&passkey_code)).await.err(),
            Some(Refusal::Invalid),
            "a second sign-in with the same password must not ride on this ceremony"
        );
        let step_up_with = |passkey_code: &str| {
            regenerate_recovery_codes(
                State(pool.clone()),
                Extension(AuthUser(user.uid)),
                Extension(SeedCipher::for_tests()),
                Json(passkey(passkey_code)),
            )
        };
        assert_eq!(step_up_with(&passkey_code).await.err(), Some(Refusal::Invalid));

        let session = sign_in_with(&pool, &mine.pending_token, passkey(&passkey_code)).await.expect("signed in");
        assert_eq!(session.user_id, user.uid);
        assert_eq!(
            sign_in_with(&pool, &mine.pending_token, passkey(&passkey_code)).await.err(),
            Some(Refusal::Invalid),
            "a code opens one session"
        );

        let confirmed = step_up_code(&pool, user.uid, &mut user.device).await;
        assert_eq!(
            sign_in_with(&pool, &mine.pending_token, passkey(&confirmed)).await.err(),
            Some(Refusal::Invalid),
            "a step-up code is not a sign-in"
        );
        assert!(step_up_with(&confirmed).await.is_ok());
    }

    #[tokio::test]
    async fn the_portal_keeps_the_code_and_the_phone_gets_a_deep_link() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let mut user = with_passkey(&pool).await;
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;

        for (return_to, in_body) in [(ReturnTo::Inline, true), (phone(), false)] {
            let handle = open_sign_in(&pool, &challenge.pending_token, return_to).await.expect("handle");
            let response = user.device.answer(&pool, &handle).await.expect("assertion");
            let done = submit(&pool, &handle, response).await.expect("finish");
            assert_eq!(done.code.is_some(), in_body);
            assert_eq!(done.redirect.is_some_and(|url| url.starts_with("voltius://passkey?c=")), !in_body);
        }
        assert_eq!(
            open_sign_in(&pool, &challenge.pending_token, ReturnTo::Loopback { port: 80, state: String::new() }).await.err(),
            Some(Refusal::Status(StatusCode::BAD_REQUEST))
        );
        assert_eq!(
            open_sign_in(&pool, "not-a-token", phone()).await.err(),
            Some(Refusal::Status(StatusCode::UNAUTHORIZED))
        );
    }

    #[tokio::test]
    async fn an_assertion_answers_one_challenge_and_a_handle_runs_one_ceremony() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let mut user = with_passkey(&pool).await;
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;

        let first = open_sign_in(&pool, &challenge.pending_token, phone()).await.expect("handle");
        let untouched = Handle { handle: first.handle.clone(), url: String::new() };
        assert_eq!(
            submit(&pool, &untouched, serde_json::json!({})).await.err(),
            Some(Refusal::Status(StatusCode::GONE)),
            "nothing to finish before a challenge was issued"
        );
        let response = user.device.answer(&pool, &first).await.expect("assertion");
        assert!(submit(&pool, &first, response.clone()).await.is_ok());
        assert_eq!(submit(&pool, &first, response.clone()).await.err(), Some(Refusal::Status(StatusCode::GONE)));

        let second = open_sign_in(&pool, &challenge.pending_token, phone()).await.expect("handle");
        user.device.answer(&pool, &second).await.expect("a fresh challenge");
        assert_eq!(submit(&pool, &second, response).await.err(), Some(Refusal::Invalid));

        let unknown = Handle { handle: "nobody-opened-this".to_string(), url: String::new() };
        assert_eq!(user.device.answer(&pool, &unknown).await.err(), Some(Refusal::Status(StatusCode::GONE)));

        sqlx::query("UPDATE users SET totp_locked_until = now() + interval '1 minute' WHERE id = $1")
            .bind(user.uid)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(user.device.answer(&pool, &second).await.err(), Some(Refusal::Locked));
    }

    #[tokio::test]
    async fn another_factor_needs_proof_of_one_already_held() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let mut user = with_passkey(&pool).await;
        let mut second_device = Device::new();

        assert_eq!(
            add_passkey(&pool, user.uid, &mut second_device, SecondFactorProof::default()).await.err(),
            Some(Refusal::Required)
        );
        let proof = passkey(&step_up_code(&pool, user.uid, &mut user.device).await);
        let second = add_passkey(&pool, user.uid, &mut second_device, proof).await.expect("second passkey");
        assert!(second.added.recovery_codes.is_empty(), "the first set of recovery codes stays valid");
        assert!(refreshes(&pool, &user.added.added.session.refresh_token).await, "nobody is signed out");

        let cipher = SeedCipher::for_tests();
        assert_eq!(
            begin_setup_with(&pool, &cipher, user.uid, SecondFactorProof::default()).await.err(),
            Some(Refusal::Required)
        );
        let proof = passkey(&step_up_code(&pool, user.uid, &mut second_device).await);
        let seed = begin_setup_with(&pool, &cipher, user.uid, proof).await.expect("setup");

        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        let pending_code = two_factor::totp_at(&seed, two_factor::current_step());
        assert_eq!(
            sign_in_with(&pool, &challenge.pending_token, code(&pending_code)).await.err(),
            Some(Refusal::Invalid),
            "a seed is no factor until its first code confirmed it"
        );

        let enabled = confirm(&pool, user.uid, code(&pending_code)).await.expect("enable");
        assert!(enabled.recovery_codes.is_empty());
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        assert_eq!(challenge.methods, ["totp", "passkey", "recovery"]);
    }

    #[tokio::test]
    async fn removing_the_last_factor_turns_two_factor_off() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = enrol(&pool).await;
        let mut device = Device::new();
        let proof = code(&unused_code(&pool, &user).await);
        let added = add_passkey(&pool, user.uid, &mut device, proof).await.expect("passkey");

        let proof = code(&unused_code(&pool, &user).await);
        let Json(without_totp) = remove_totp(
            State(pool.clone()),
            Extension(AuthUser(user.uid)),
            Extension(SeedCipher::for_tests()),
            Extension(SyncNotifier::new()),
            Json(step_up_request(AUTH_KEY, proof)),
        )
        .await
        .expect("authenticator removed");
        assert!(without_totp.two_factor_enabled);
        assert!(refreshes(&pool, &user.session.refresh_token).await);
        let challenge = challenge_with(&pool, SeedCipher::for_tests(), user.account_id).await;
        assert_eq!(challenge.methods, ["passkey", "recovery"]);

        assert_eq!(
            remove_one(&pool, user.uid, Uuid::new_v4(), recovery(&user.recovery_codes[0])).await.err(),
            Some(Refusal::Status(StatusCode::NOT_FOUND))
        );
        let proof = passkey(&step_up_code(&pool, user.uid, &mut device).await);
        let off = remove_one(&pool, user.uid, added.passkey.id, proof).await.expect("passkey removed");
        assert!(!off.two_factor_enabled);
        assert!(!refreshes(&pool, &user.session.refresh_token).await);
        assert!(refreshes(&pool, &off.session.refresh_token).await);
        assert!(signs_in_with_the_password_alone(&pool, user.account_id).await);
        let leftover: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = $1")
            .bind(user.uid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(leftover, 0);
    }

    #[tokio::test]
    async fn an_admin_clear_removes_passkeys_too() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = with_passkey(&pool).await;

        let mut tx = pool.begin().await.unwrap();
        assert!(two_factor::clear(&mut tx, user.uid).await.unwrap());
        assert!(!two_factor::clear(&mut tx, user.uid).await.unwrap());
        tx.commit().await.unwrap();

        assert!(signs_in_with_the_password_alone(&pool, user.account_id).await);
        assert!(!refreshes(&pool, &user.added.added.session.refresh_token).await);
    }

    #[tokio::test]
    async fn a_server_without_a_relying_party_offers_no_passkeys() {
        let _env = jwt_env();
        let pool = test_pool_or_skip!();
        let user = with_passkey(&pool).await;

        assert_eq!(
            open_registration(&pool, Passkeys::absent(), user.uid, SecondFactorProof::default()).await.err(),
            Some(Refusal::Unavailable)
        );
        let offered = two_factor::methods(&pool, &SeedCipher::for_tests(), &Passkeys::absent(), user.uid).await;
        assert_eq!(offered, Ok(vec!["recovery"]));
    }
}
