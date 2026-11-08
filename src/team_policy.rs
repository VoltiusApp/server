use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

pub const LOCK_MINUTES: [i32; 6] = [0, 5, 15, 30, 60, 240];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockPolicy {
    pub max_minutes: i32,
    pub force_vault: bool,
}

impl LockPolicy {
    pub fn from_columns(max_minutes: Option<i32>, force_vault: bool) -> Option<Self> {
        max_minutes.map(|max_minutes| Self {
            max_minutes,
            force_vault,
        })
    }
}

pub const MACHINE_ONLY_KEYS: [&str; 5] = [
    "server.url",
    "server.allowOther",
    "server.previousUrls",
    "enrollment.token",
    "plugins.install",
];

pub const LOCK_POLICY_BACKFILL: &str = "UPDATE teams SET policy = jsonb_build_object('version', 1, 'policy', jsonb_build_object('security.lockTimeoutMinutes', jsonb_build_object('$range', jsonb_build_object('max', lock_max_minutes))) || CASE WHEN lock_force_vault THEN jsonb_build_object('security.lockAction', 'vault') ELSE '{}'::jsonb END), policy_revision = 1 WHERE lock_max_minutes IS NOT NULL AND policy IS NULL;";

const MAX_BYTES: usize = 65_536;
const MAX_KEYS: usize = 500;
const MAX_KEY_LEN: usize = 128;
const TIMEOUT_KEY: &str = "security.lockTimeoutMinutes";
const ACTION_KEY: &str = "security.lockAction";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocError {
    Invalid(String),
    TooLarge,
    DefaultsUnsupported,
    MachineOnlyKey(String),
}

impl DocError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "POLICY_INVALID",
            Self::TooLarge => "POLICY_TOO_LARGE",
            Self::DefaultsUnsupported => "TEAM_DEFAULTS_UNSUPPORTED",
            Self::MachineOnlyKey(_) => "POLICY_MACHINE_ONLY_KEY",
        }
    }

    pub fn key(&self) -> Option<&str> {
        match self {
            Self::MachineOnlyKey(k) => Some(k),
            _ => None,
        }
    }
}

fn invalid(msg: &str) -> DocError {
    DocError::Invalid(msg.to_string())
}

fn valid_key(k: &str) -> bool {
    (1..=MAX_KEY_LEN).contains(&k.len())
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn valid_range(v: &Value) -> bool {
    let Some(r) = v.as_object() else { return false };
    r.iter().all(|(k, v)| match k.as_str() {
        "min" | "max" => v.is_number(),
        "allowed" => v.is_array(),
        _ => false,
    })
}

pub fn validate_doc(doc: &Value) -> Result<(), DocError> {
    let bytes = serde_json::to_vec(doc).map_err(|_| invalid("unserializable"))?;
    if bytes.len() > MAX_BYTES {
        return Err(DocError::TooLarge);
    }
    let obj = doc.as_object().ok_or_else(|| invalid("not an object"))?;
    if obj.get("version") != Some(&json!(1)) {
        return Err(invalid("version must be 1"));
    }
    match obj.get("defaults") {
        None => {}
        Some(Value::Object(d)) if d.is_empty() => {}
        Some(Value::Object(_)) => return Err(DocError::DefaultsUnsupported),
        Some(_) => return Err(invalid("defaults must be an object")),
    }
    let policy = obj
        .get("policy")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("policy must be an object"))?;
    if policy.len() > MAX_KEYS {
        return Err(invalid("too many policy keys"));
    }
    for (k, v) in policy {
        if MACHINE_ONLY_KEYS.contains(&k.as_str()) {
            return Err(DocError::MachineOnlyKey(k.clone()));
        }
        if !valid_key(k) {
            return Err(invalid("bad policy key"));
        }
        if let Some(range) = v.as_object().and_then(|o| o.get("$range")) {
            if !valid_range(range) {
                return Err(invalid("bad $range"));
            }
        }
    }
    Ok(())
}

pub fn with_lock_policy(doc: Option<Value>, lp: Option<LockPolicy>) -> Option<Value> {
    let mut doc = doc.unwrap_or_else(|| json!({"version": 1, "policy": {}}));
    let policy = doc.get_mut("policy").and_then(Value::as_object_mut)?;
    policy.remove(TIMEOUT_KEY);
    policy.remove(ACTION_KEY);
    if let Some(lp) = lp {
        policy.insert(TIMEOUT_KEY.into(), json!({"$range": {"max": lp.max_minutes}}));
        if lp.force_vault {
            policy.insert(ACTION_KEY.into(), json!("vault"));
        }
    }
    (!policy.is_empty()).then_some(doc)
}

pub fn lock_policy_of(doc: Option<&Value>) -> Option<LockPolicy> {
    let policy = policy_map(doc)?;
    let max = policy.get(TIMEOUT_KEY)?.get("$range")?.get("max")?.as_f64()?;
    let max_minutes = LOCK_MINUTES
        .iter()
        .rev()
        .copied()
        .find(|m| f64::from(*m) <= max)
        .unwrap_or(0);
    Some(LockPolicy {
        max_minutes,
        force_vault: policy.get(ACTION_KEY) == Some(&json!("vault")),
    })
}

fn policy_map(doc: Option<&Value>) -> Option<&Map<String, Value>> {
    doc?.get("policy")?.as_object()
}

pub fn is_narrowing(stored: Option<&Value>, new: &Value) -> bool {
    let Some(new) = policy_map(Some(new)) else {
        return false;
    };
    let stored = policy_map(stored);
    new.iter()
        .all(|(k, v)| stored.and_then(|s| s.get(k)) == Some(v))
}

pub fn key_diff(old: Option<&Value>, new: Option<&Value>) -> Value {
    let (old, new) = (policy_map(old), policy_map(new));
    let keys: BTreeSet<&String> = old.into_iter().chain(new).flat_map(|m| m.keys()).collect();
    let (mut added, mut changed, mut removed) = (vec![], vec![], vec![]);
    for k in keys {
        match (old.and_then(|m| m.get(k)), new.and_then(|m| m.get(k))) {
            (None, Some(_)) => added.push(k),
            (Some(_), None) => removed.push(k),
            (Some(a), Some(b)) if a != b => changed.push(k),
            _ => {}
        }
    }
    json!({"added": added, "changed": changed, "removed": removed})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{seed_team_with_roles, seed_user};

    fn doc(policy: Value) -> Value {
        json!({"version": 1, "policy": policy})
    }

    fn lp(max_minutes: i32, force_vault: bool) -> LockPolicy {
        LockPolicy {
            max_minutes,
            force_vault,
        }
    }

    #[test]
    fn accepts_minimal_doc() {
        assert_eq!(validate_doc(&doc(json!({"sync.types.key": false}))), Ok(()));
    }

    #[test]
    fn rejects_bad_shapes() {
        let long = "a".repeat(129);
        let bad = [
            json!({"version": 2, "policy": {}}),
            json!({"version": "1", "policy": {}}),
            json!({"version": 1, "policy": []}),
            doc(json!({"bad key": 1})),
            doc(json!({ long: 1 })),
            doc(json!({"a.b": {"$range": {"max": 5, "step": 1}}})),
            doc(json!({"a.b": {"$range": {"max": "5"}}})),
        ];
        for d in bad {
            assert!(matches!(validate_doc(&d), Err(DocError::Invalid(_))), "{d}");
        }
    }

    #[test]
    fn rejects_defaults() {
        let with = |defaults: Value| json!({"version": 1, "policy": {}, "defaults": defaults});
        assert_eq!(
            validate_doc(&with(json!({"a.b": 1}))),
            Err(DocError::DefaultsUnsupported)
        );
        assert_eq!(validate_doc(&with(json!({}))), Ok(()));
    }

    #[test]
    fn rejects_each_machine_only_key() {
        for k in MACHINE_ONLY_KEYS {
            let err = validate_doc(&doc(json!({ k: 1 }))).unwrap_err();
            assert_eq!(err, DocError::MachineOnlyKey(k.to_string()));
            assert_eq!(err.code(), "POLICY_MACHINE_ONLY_KEY");
            assert_eq!(err.key(), Some(k));
        }
    }

    #[test]
    fn rejects_oversize() {
        let many: Map<String, Value> = (0..501).map(|i| (format!("k{i}"), json!(1))).collect();
        assert!(matches!(
            validate_doc(&doc(Value::Object(many))),
            Err(DocError::Invalid(_))
        ));
        let big = doc(json!({"a.b": "x".repeat(70 * 1024)}));
        assert_eq!(validate_doc(&big), Err(DocError::TooLarge));
    }

    #[test]
    fn lock_policy_round_trip() {
        let expected = doc(json!({
            "security.lockTimeoutMinutes": {"$range": {"max": 15}},
            "security.lockAction": "vault"
        }));
        let made = with_lock_policy(None, Some(lp(15, true))).unwrap();
        assert_eq!(made, expected);
        assert_eq!(lock_policy_of(Some(&made)), Some(lp(15, true)));
        assert_eq!(with_lock_policy(Some(made), None), None);

        let mut other = expected.clone();
        other["policy"]["sync.types.key"] = json!(false);
        assert_eq!(
            with_lock_policy(Some(other), None),
            Some(doc(json!({"sync.types.key": false})))
        );
    }

    #[test]
    fn lock_policy_of_rounds_down() {
        let range = |max: i64| doc(json!({"security.lockTimeoutMinutes": {"$range": {"max": max}}}));
        assert_eq!(lock_policy_of(Some(&range(20))), Some(lp(15, false)));
        assert_eq!(lock_policy_of(Some(&range(3))), Some(lp(0, false)));
        assert_eq!(lock_policy_of(Some(&doc(json!({"a.b": 1})))), None);
        assert_eq!(lock_policy_of(None), None);
        let screen = doc(json!({
            "security.lockTimeoutMinutes": {"$range": {"max": 5}},
            "security.lockAction": "screen"
        }));
        assert_eq!(lock_policy_of(Some(&screen)), Some(lp(5, false)));
    }

    #[test]
    fn narrowing() {
        let stored = doc(json!({"a.b": 1, "c.d": 2}));
        assert!(is_narrowing(Some(&stored), &doc(json!({"a.b": 1}))));
        assert!(!is_narrowing(Some(&stored), &doc(json!({"a.b": 9}))));
        assert!(!is_narrowing(Some(&stored), &doc(json!({"a.b": 1, "x.y": 1}))));
        assert!(is_narrowing(None, &doc(json!({}))));
        assert!(!is_narrowing(None, &doc(json!({"a.b": 1}))));
    }

    #[test]
    fn key_diff_lists_keys() {
        let old = doc(json!({"a.b": 1, "c.d": 2, "e.f": 3}));
        let new = doc(json!({"a.b": 1, "c.d": 9, "g.h": 4}));
        assert_eq!(
            key_diff(Some(&old), Some(&new)),
            json!({"added": ["g.h"], "changed": ["c.d"], "removed": ["e.f"]})
        );
        assert_eq!(
            key_diff(None, Some(&new)),
            json!({"added": ["a.b", "c.d", "g.h"], "changed": [], "removed": []})
        );
    }

    #[test]
    fn migration_contains_backfill() {
        assert!(include_str!("../migrations/067_team_policy.sql").contains(LOCK_POLICY_BACKFILL));
    }

    #[tokio::test]
    async fn boot_backfill_matches_with_lock_policy() {
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        for force_vault in [true, false] {
            sqlx::query(
                "UPDATE teams SET lock_max_minutes = 15, lock_force_vault = $2, policy = NULL WHERE id = $1",
            )
            .bind(team)
            .bind(force_vault)
            .execute(&pool)
            .await
            .unwrap();
            crate::db::backfill_team_policies(&pool).await;
            let stored: Option<Value> = sqlx::query_scalar("SELECT policy FROM teams WHERE id = $1")
                .bind(team)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(stored, with_lock_policy(None, Some(lp(15, force_vault))));
        }
    }
}
