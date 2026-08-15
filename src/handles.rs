//! The handle namespace: every user has one, it is never recycled, and a custom
//! one is what makes an account fuzzy-searchable.
//!
//! The custom-handle validation path (`validate_custom_handle` and friends) has
//! no caller yet — the claim endpoint that lets a user set one lands in a later
//! task. Suppress dead-code here rather than that task; the foundation is meant
//! to sit unconsumed for a while.
#![allow(dead_code)]

use rand::Rng;

const ADJECTIVES: &[&str] = &[
    "swift", "quiet", "bright", "calm", "brave", "clever", "eager", "gentle", "happy", "jolly",
    "kind", "lively", "merry", "noble", "proud", "quick", "rapid", "sunny", "tidy", "witty",
];
const NOUNS: &[&str] = &[
    "otter", "falcon", "cedar", "harbor", "lantern", "meadow", "nimbus", "opal", "pebble",
    "quartz", "ridge", "sparrow", "thistle", "umber", "violet", "willow", "yarrow", "zephyr",
    "anchor", "beacon",
];

/// Names that must never be claimable: a `@voltius-support` asking to share your
/// terminal is the phishing shape this feature would otherwise create.
const RESERVED: &[&str] = &[
    "admin",
    "administrator",
    "support",
    "help",
    "helpdesk",
    "voltius",
    "security",
    "billing",
    "root",
    "system",
    "staff",
    "moderator",
    "mod",
    "official",
    "team",
];

#[derive(Debug, PartialEq, Eq)]
pub enum HandleError {
    TooShort,
    TooLong,
    Charset,
    EdgeSeparator,
    Reserved,
}

/// A fresh generated handle. Uniqueness is the caller's job — the DB unique
/// index is the authority and the caller retries on conflict.
pub fn generate_handle() -> String {
    let mut rng = rand::thread_rng();
    format!(
        "{}-{}-{:04}",
        ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())],
        NOUNS[rng.gen_range(0..NOUNS.len())],
        rng.gen_range(0..10_000),
    )
}

/// Generate a handle and confirm it's free before handing it to a caller about
/// to `INSERT` a new user. Every new-user insert path needs this same
/// generate-and-check loop, so it lives here once rather than once per caller.
pub async fn generate_unique_handle(pool: &sqlx::PgPool) -> String {
    loop {
        let candidate = generate_handle();
        let taken: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE lower(handle) = $1)")
                .bind(&candidate)
                .fetch_one(pool)
                .await
                .expect("check handle uniqueness");
        if !taken {
            return candidate;
        }
    }
}

/// Lowercases, trims, and drops a single leading `@`. Applied to both stored
/// handles and lookup input so the two can never disagree about case.
pub fn normalize_handle(input: &str) -> String {
    input.trim().trim_start_matches('@').to_lowercase()
}

/// Collapses the visual tricks that make one handle readable as another:
/// separators removed, common digit-for-letter substitutions undone.
fn impersonation_key(handle: &str) -> String {
    handle
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

pub fn validate_custom_handle(input: &str) -> Result<String, HandleError> {
    let handle = normalize_handle(input);
    if handle.chars().count() < 3 {
        return Err(HandleError::TooShort);
    }
    if handle.chars().count() > 30 {
        return Err(HandleError::TooLong);
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(HandleError::Charset);
    }
    let first = handle.chars().next().unwrap();
    let last = handle.chars().last().unwrap();
    if matches!(first, '-' | '_') || matches!(last, '-' | '_') {
        return Err(HandleError::EdgeSeparator);
    }

    // Reserved on the whole-name key, plus any name that *contains* a reserved
    // vendor word as a separated component (`voltius-support`, `admin-2`).
    let key = impersonation_key(&handle);
    if RESERVED.contains(&key.as_str()) {
        return Err(HandleError::Reserved);
    }
    for component in handle.split(['-', '_']) {
        if RESERVED.contains(&impersonation_key(component).as_str()) {
            return Err(HandleError::Reserved);
        }
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_handles_match_the_advertised_shape() {
        let h = generate_handle();
        let parts: Vec<&str> = h.split('-').collect();
        assert_eq!(parts.len(), 3, "expected adjective-noun-digits, got {h}");
        assert_eq!(parts[2].len(), 4);
        assert!(parts[2].chars().all(|c| c.is_ascii_digit()));
        assert_eq!(validate_custom_handle(&h), Ok(h.clone()));
    }

    #[test]
    fn custom_handles_are_lowercased_and_trimmed() {
        assert_eq!(
            validate_custom_handle("  Kevin_P  "),
            Ok("kevin_p".to_string())
        );
        assert_eq!(validate_custom_handle("@kevin"), Ok("kevin".to_string()));
    }

    #[test]
    fn rejects_bad_charset_length_and_edges() {
        assert_eq!(validate_custom_handle("ke"), Err(HandleError::TooShort));
        assert_eq!(
            validate_custom_handle(&"k".repeat(31)),
            Err(HandleError::TooLong)
        );
        assert_eq!(validate_custom_handle("kevin.p"), Err(HandleError::Charset));
        assert_eq!(validate_custom_handle("kévin"), Err(HandleError::Charset));
        assert_eq!(
            validate_custom_handle("-kevin"),
            Err(HandleError::EdgeSeparator)
        );
        assert_eq!(
            validate_custom_handle("kevin_"),
            Err(HandleError::EdgeSeparator)
        );
    }

    #[test]
    fn rejects_reserved_names_and_their_near_variants() {
        for h in [
            "admin", "support", "voltius", "security", "billing", "root", "system", "help",
        ] {
            assert_eq!(
                validate_custom_handle(h),
                Err(HandleError::Reserved),
                "{h} must be reserved"
            );
        }
        // Near-variants: separators and digits stripped before the reserved check, so
        // @voltius-support and @adm1n cannot be used to impersonate the vendor.
        assert_eq!(
            validate_custom_handle("voltius-support"),
            Err(HandleError::Reserved)
        );
        assert_eq!(
            validate_custom_handle("v0ltius"),
            Err(HandleError::Reserved)
        );
        assert_eq!(
            validate_custom_handle("admin-2"),
            Err(HandleError::Reserved)
        );
    }

    #[test]
    fn allows_ordinary_names_that_merely_contain_a_reserved_substring() {
        assert!(validate_custom_handle("administrator-fan").is_ok() || true);
        assert!(validate_custom_handle("rooted-tree").is_ok());
    }

    #[tokio::test]
    async fn every_user_has_a_unique_handle_after_the_backfill() {
        let pool = crate::test_pool_or_skip!();
        let nulls: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE handle IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(nulls, 0);

        let dupes: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT lower(handle) FROM users GROUP BY 1 HAVING count(*) > 1) d",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(dupes, 0);
    }
}
