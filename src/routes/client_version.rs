/// Minimum client version permitted to WRITE team vault objects, from
/// `TEAM_OBJECTS_MIN_CLIENT_VERSION`. `None` disables the gate entirely, which
/// is the default so self-hosted deployments are unaffected until an operator
/// opts in.
///
/// This is a COMPATIBILITY control, not a security control: the header is
/// client-supplied and trivially spoofable. Its only job is to stop clients
/// that predate #229 from overwriting encrypted metadata with the degraded
/// plaintext object they were unable to decrypt. Never use it for authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinClientVersion(pub Option<(u32, u32, u32)>);

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let mut parts = v.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch_raw = parts.next()?;
    // Tolerate a pre-release or build suffix: "0.33.0-beta.1" -> patch 0.
    let patch = patch_raw.split(['-', '+']).next()?.parse().ok()?;
    Some((major, minor, patch))
}

impl MinClientVersion {
    pub fn from_env_value(value: Option<&str>) -> Self {
        MinClientVersion(value.and_then(parse_semver))
    }
}

/// True when the request may proceed. A missing or unparseable header is
/// treated as below the floor, so a client that does not send the header at
/// all is refused once an operator sets one.
pub fn client_version_allowed(floor: &MinClientVersion, header: Option<&str>) -> bool {
    let Some(floor) = floor.0 else { return true };
    match header.and_then(parse_semver) {
        Some(v) => v >= floor,
        None => false,
    }
}

/// Returns `Err(UPGRADE_REQUIRED)` when the caller is below the configured
/// floor. Call first in every handler that WRITES team vault objects.
pub fn require_client_version(
    floor: &MinClientVersion,
    headers: &axum::http::HeaderMap,
) -> Result<(), axum::http::StatusCode> {
    if client_version_allowed(
        floor,
        headers
            .get("x-client-version")
            .and_then(|v| v.to_str().ok()),
    ) {
        Ok(())
    } else {
        Err(axum::http::StatusCode::UPGRADE_REQUIRED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_floor_allows_everything_including_a_missing_header() {
        let floor = MinClientVersion(None);
        assert!(client_version_allowed(&floor, None));
        assert!(client_version_allowed(&floor, Some("0.1.0")));
        assert!(client_version_allowed(&floor, Some("garbage")));
    }

    #[test]
    fn set_floor_rejects_older_and_missing_and_unparseable() {
        let floor = MinClientVersion(Some((0, 33, 0)));
        assert!(
            !client_version_allowed(&floor, None),
            "missing header counts as below floor"
        );
        assert!(!client_version_allowed(&floor, Some("0.32.1")));
        assert!(!client_version_allowed(&floor, Some("garbage")));
    }

    #[test]
    fn set_floor_allows_equal_and_newer() {
        let floor = MinClientVersion(Some((0, 33, 0)));
        assert!(client_version_allowed(&floor, Some("0.33.0")));
        assert!(client_version_allowed(&floor, Some("0.33.1")));
        assert!(client_version_allowed(&floor, Some("1.0.0")));
        assert!(client_version_allowed(&floor, Some("0.34.0")));
    }

    #[test]
    fn parses_floor_from_env_value() {
        assert_eq!(MinClientVersion::from_env_value(None).0, None);
        assert_eq!(
            MinClientVersion::from_env_value(Some("0.33.0")).0,
            Some((0, 33, 0))
        );
        // A malformed floor must disable the gate, never enable it against
        // everyone — a typo in deployment config must not lock out a fleet.
        assert_eq!(MinClientVersion::from_env_value(Some("nonsense")).0, None);
    }
}
