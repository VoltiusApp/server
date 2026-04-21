use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash auth_key with Argon2id for storage.
pub fn hash_auth_key(auth_key: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(auth_key.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify auth_key against stored hash.
pub fn verify_auth_key(auth_key: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(auth_key.as_bytes(), &parsed)
        .is_ok())
}
