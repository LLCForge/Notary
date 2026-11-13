//! RFC 6811 Route Origin Validation. Pure functions, no I/O.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::prefix::Prefix;
use crate::vrp::{Vrp, VrpTable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidReason {
    /// No covering VRP authorises this origin AS.
    WrongOrigin,
    /// A VRP authorises the origin, but the route is more specific than its maxLength.
    MaxLengthExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum Validity {
    Valid,
    Invalid(InvalidReason),
    NotFound,
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Validity::Valid => f.write_str("VALID"),
            Validity::Invalid(InvalidReason::WrongOrigin) => f.write_str("INVALID (wrong origin)"),
            Validity::Invalid(InvalidReason::MaxLengthExceeded) => {
                f.write_str("INVALID (maxLength exceeded)")
            }
            Validity::NotFound => f.write_str("NOT FOUND"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Validation {
    pub prefix: Prefix,
    pub origin: u32,
    #[serde(flatten)]
    pub validity: Validity,
    /// Every VRP covering the route prefix, sorted.
    pub covering: Vec<Vrp>,
}

/// Does `vrp` authorise `origin` announcing `prefix`? AS0 VRPs never match
/// (RFC 6483 section 4 / RFC 7607).
pub fn matches(vrp: &Vrp, prefix: &Prefix, origin: u32) -> bool {
    vrp.asn != 0 && vrp.asn == origin && prefix.len() <= vrp.max_length
}

pub fn validate(table: &VrpTable, prefix: &Prefix, origin: u32) -> Validation {
    let mut covering = table.covering(prefix);
    covering.sort_unstable();
    debug_assert!(covering.iter().all(|v| v.prefix.covers(prefix)));
    let validity = classify(&covering, prefix, origin);
    Validation {
        prefix: *prefix,
        origin,
        validity,
        covering,
    }
}

/// Classifies a route given the VRPs that cover it.
pub fn classify(covering: &[Vrp], prefix: &Prefix, origin: u32) -> Validity {
    if covering.is_empty() {
        Validity::NotFound
    } else if covering.iter().any(|v| matches(v, prefix, origin)) {
        Validity::Valid
    } else if covering.iter().any(|v| v.asn != 0 && v.asn == origin) {
        Validity::Invalid(InvalidReason::MaxLengthExceeded)
    } else {
        Validity::Invalid(InvalidReason::WrongOrigin)
    }
}

/// One-line human explanation of why a single covering VRP did or did not match.
pub fn explain_vrp(vrp: &Vrp, prefix: &Prefix, origin: u32) -> &'static str {
    if vrp.asn == 0 {
        "AS0 ROA: nothing may originate this space"
    } else if vrp.asn != origin {
        "origin mismatch"
    } else if prefix.len() > vrp.max_length {
        "origin matches, but route is longer than maxLength"
    } else {
        "matches"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp(p: &str, max: u8, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), max, asn).unwrap()
    }

    fn check(vrps: &[Vrp], prefix: &str, origin: u32) -> Validity {
        let t = VrpTable::from_vrps(vrps.iter().copied());
        validate(&t, &prefix.parse().unwrap(), origin).validity
    }

    #[test]
    fn not_found_without_covering_vrp() {
        let v = [vrp("198.51.100.0/24", 24, 64500)];
        assert_eq!(check(&v, "203.0.113.0/24", 64500), Validity::NotFound);
        // A more specific VRP does not cover a less specific route.
        assert_eq!(check(&v, "198.51.100.0/23", 64500), Validity::NotFound);
        assert_eq!(check(&[], "192.0.2.0/24", 64500), Validity::NotFound);
    }

    #[test]
    fn valid_exact_match() {
        let v = [vrp("198.51.100.0/24", 24, 64500)];
        assert_eq!(check(&v, "198.51.100.0/24", 64500), Validity::Valid);
    }

    #[test]
    fn max_length_equal_to_prefix_length() {
        let v = [vrp("198.51.100.0/22", 22, 64500)];
        assert_eq!(check(&v, "198.51.100.0/22", 64500), Validity::Valid);
        assert_eq!(
            check(&v, "198.51.100.0/23", 64500),
            Validity::Invalid(InvalidReason::MaxLengthExceeded)
        );
    }

    #[test]
    fn max_length_range() {
        let v = [vrp("198.51.100.0/22", 24, 64500)];
        assert_eq!(check(&v, "198.51.101.0/24", 64500), Validity::Valid);
        assert_eq!(
            check(&v, "198.51.101.0/25", 64500),
            Validity::Invalid(InvalidReason::MaxLengthExceeded)
        );
    }

    #[test]
    fn wrong_origin() {
        let v = [vrp("198.51.100.0/24", 24, 64500)];
        assert_eq!(
            check(&v, "198.51.100.0/24", 64501),
            Validity::Invalid(InvalidReason::WrongOrigin)
        );
    }

    #[test]
    fn wrong_origin_wins_over_max_length_when_origin_never_listed() {
        // Origin differs AND route is too long: reason is wrong origin.
        let v = [vrp("198.51.100.0/24", 24, 64500)];
        assert_eq!(
            check(&v, "198.51.100.0/25", 64501),
            Validity::Invalid(InvalidReason::WrongOrigin)
        );
    }

    #[test]
    fn multiple_covering_vrps_any_match_is_valid() {
        let v = [
            vrp("198.51.100.0/22", 22, 64500),
            vrp("198.51.100.0/24", 24, 64501),
            vrp("198.51.100.0/23", 24, 64502),
        ];
        assert_eq!(check(&v, "198.51.100.0/24", 64501), Validity::Valid);
        assert_eq!(check(&v, "198.51.100.0/24", 64502), Validity::Valid);
        assert_eq!(
            check(&v, "198.51.100.0/24", 64500),
            Validity::Invalid(InvalidReason::MaxLengthExceeded)
        );
        assert_eq!(
            check(&v, "198.51.100.0/24", 64503),
            Validity::Invalid(InvalidReason::WrongOrigin)
        );
        let t = VrpTable::from_vrps(v);
        let r = validate(&t, &"198.51.100.0/24".parse().unwrap(), 64503);
        assert_eq!(r.covering.len(), 3);
    }

    #[test]
    fn as0_roa_makes_everything_invalid() {
        let v = [vrp("203.0.113.0/24", 32, 0)];
        assert_eq!(
            check(&v, "203.0.113.0/24", 64500),
            Validity::Invalid(InvalidReason::WrongOrigin)
        );
        // Even a route "originated" by AS0 does not match an AS0 ROA.
        assert_eq!(
            check(&v, "203.0.113.0/24", 0),
            Validity::Invalid(InvalidReason::WrongOrigin)
        );
    }

    #[test]
    fn as0_roa_does_not_override_real_roa() {
        let v = [
            vrp("203.0.113.0/24", 24, 0),
            vrp("203.0.113.0/24", 24, 64500),
        ];
        assert_eq!(check(&v, "203.0.113.0/24", 64500), Validity::Valid);
    }

    #[test]
    fn ipv6() {
        let v = [vrp("2001:db8::/32", 48, 64500)];
        assert_eq!(check(&v, "2001:db8:1234::/48", 64500), Validity::Valid);
        assert_eq!(
            check(&v, "2001:db8:1234:5600::/56", 64500),
            Validity::Invalid(InvalidReason::MaxLengthExceeded)
        );
        assert_eq!(
            check(&v, "2001:db8::/32", 64501),
            Validity::Invalid(InvalidReason::WrongOrigin)
        );
        assert_eq!(check(&v, "2001:db9::/32", 64500), Validity::NotFound);
        // IPv4 VRPs never cover IPv6 routes.
        let v4 = [vrp("0.0.0.0/0", 32, 64500)];
        assert_eq!(check(&v4, "2001:db8::/32", 64500), Validity::NotFound);
    }

    #[test]
    fn host_routes() {
        let v = [vrp("192.0.2.0/24", 32, 64500)];
        assert_eq!(check(&v, "192.0.2.7/32", 64500), Validity::Valid);
        let v = [vrp("2001:db8::/32", 128, 64500)];
        assert_eq!(check(&v, "2001:db8::1/128", 64500), Validity::Valid);
    }

    #[test]
    fn json_shape() {
        let t = VrpTable::from_vrps([vrp("192.0.2.0/24", 24, 64500)]);
        let r = validate(&t, &"192.0.2.0/24".parse().unwrap(), 64501);
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["state"], "invalid");
        assert_eq!(j["reason"], "wrong_origin");
        assert_eq!(j["covering"][0]["prefix"], "192.0.2.0/24");
        let r = validate(&t, &"192.0.2.0/24".parse().unwrap(), 64500);
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["state"], "valid");
        assert!(j.get("reason").is_none());
    }

    #[test]
    fn explanations() {
        let p: Prefix = "192.0.2.0/25".parse().unwrap();
        assert_eq!(
            explain_vrp(&vrp("192.0.2.0/24", 24, 0), &p, 64500),
            "AS0 ROA: nothing may originate this space"
        );
        assert_eq!(
            explain_vrp(&vrp("192.0.2.0/24", 24, 64501), &p, 64500),
            "origin mismatch"
        );
        assert_eq!(
            explain_vrp(&vrp("192.0.2.0/24", 24, 64500), &p, 64500),
            "origin matches, but route is longer than maxLength"
        );
        assert_eq!(
            explain_vrp(&vrp("192.0.2.0/24", 25, 64500), &p, 64500),
            "matches"
        );
    }
}
