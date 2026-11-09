#![allow(dead_code)]

use base64::Engine;
use rand::RngCore;

pub fn mint_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReason {
    Approval,
    EmailUnverified,
    SeatLimit,
}

impl PendingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            PendingReason::Approval => "approval",
            PendingReason::EmailUnverified => "email_unverified",
            PendingReason::SeatLimit => "seat_limit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admit,
    Pending(PendingReason),
    DomainMismatch,
}

#[derive(Debug, Clone)]
pub struct Guard {
    pub allowed_domains: Vec<String>,
    pub require_approval: bool,
}

pub fn admission(guard: &Guard, email: &str, email_proven: bool, seat_available: bool) -> Admission {
    if !guard.allowed_domains.is_empty() {
        let domain = email.rsplit_once('@').map(|(_, d)| d.to_lowercase());
        if !domain.is_some_and(|d| guard.allowed_domains.contains(&d)) {
            return Admission::DomainMismatch;
        }
    }
    if guard.require_approval {
        return Admission::Pending(PendingReason::Approval);
    }
    if !email_proven {
        return Admission::Pending(PendingReason::EmailUnverified);
    }
    if !seat_available {
        return Admission::Pending(PendingReason::SeatLimit);
    }
    Admission::Admit
}

fn is_hostname(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').count() >= 2
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub fn normalize_domains(input: &[String]) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = Vec::new();
    for raw in input {
        let domain = raw.trim().to_lowercase();
        let domain = domain.strip_prefix('@').unwrap_or(&domain).to_string();
        if !is_hostname(&domain) {
            return Err(());
        }
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(domains: &[&str], approval: bool) -> Guard {
        Guard { allowed_domains: domains.iter().map(|d| d.to_string()).collect(), require_approval: approval }
    }

    #[test]
    fn domain_guard_admits_only_exact_proven_matches_with_a_seat() {
        let g = guard(&["acme.com"], false);
        assert_eq!(admission(&g, "a@acme.com", true, true), Admission::Admit);
        assert_eq!(admission(&g, "A@ACME.COM", true, true), Admission::Admit);
        assert_eq!(admission(&g, "a@acme.com", false, true), Admission::Pending(PendingReason::EmailUnverified));
        assert_eq!(admission(&g, "a@acme.com", true, false), Admission::Pending(PendingReason::SeatLimit));
        assert_eq!(admission(&g, "a@gmail.com", true, true), Admission::DomainMismatch);
        assert_eq!(admission(&g, "a@sub.acme.com", true, true), Admission::DomainMismatch);
    }

    #[test]
    fn approval_only_guard_makes_everyone_pending() {
        let g = guard(&[], true);
        assert_eq!(admission(&g, "a@gmail.com", true, true), Admission::Pending(PendingReason::Approval));
    }

    #[test]
    fn domain_mismatch_wins_over_approval() {
        let g = guard(&["acme.com"], true);
        assert_eq!(admission(&g, "a@gmail.com", true, true), Admission::DomainMismatch);
        assert_eq!(admission(&g, "a@acme.com", true, true), Admission::Pending(PendingReason::Approval));
    }

    #[test]
    fn pending_reasons_match_the_database_values() {
        assert_eq!(PendingReason::Approval.as_str(), "approval");
        assert_eq!(PendingReason::EmailUnverified.as_str(), "email_unverified");
        assert_eq!(PendingReason::SeatLimit.as_str(), "seat_limit");
    }

    #[test]
    fn normalize_domains_cleans_and_dedupes() {
        let input = vec![" @Acme.COM ".to_string(), "acme.com".to_string()];
        assert_eq!(normalize_domains(&input), Ok(vec!["acme.com".to_string()]));
    }

    #[test]
    fn normalize_domains_rejects_non_hostnames() {
        for bad in ["acme", "a b.com", "", "-a.com", "a-.com", "a..com", "a.com/x"] {
            assert!(normalize_domains(&[bad.to_string()]).is_err(), "{bad}");
        }
        assert!(normalize_domains(&[format!("{}.com", "a".repeat(64))]).is_err());
    }

    #[test]
    fn mint_secret_is_43_url_safe_chars() {
        let s = mint_secret();
        assert_eq!(s.len(), 43);
        assert_ne!(s, mint_secret());
    }
}
