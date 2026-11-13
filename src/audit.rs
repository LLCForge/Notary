//! ROA suggestions and the RFC 9319 maxLength looseness audit.

use serde::Serialize;

use crate::prefix::Prefix;
use crate::validator::{matches, validate, Validity};
use crate::vrp::{Vrp, VrpTable};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub prefix: Prefix,
    #[serde(rename = "maxLength")]
    pub max_length: u8,
    pub asn: u32,
    /// `covered` (an existing ROA already makes it Valid), `missing`
    /// (NotFound today) or `fixes_invalid` (Invalid today).
    pub status: &'static str,
}

/// Minimal ROAs for the announcements of `asn`: one per announced prefix,
/// maxLength = prefix length (RFC 9319 section 4). With a VRP table each
/// suggestion says whether it is already covered.
pub fn suggest(table: Option<&VrpTable>, asn: u32, announced: &[Prefix]) -> Vec<Suggestion> {
    let mut v: Vec<Suggestion> = announced
        .iter()
        .map(|&prefix| Suggestion {
            prefix,
            max_length: prefix.len(),
            asn,
            status: match table.map(|t| validate(t, &prefix, asn).validity) {
                Some(Validity::Valid) => "covered",
                Some(Validity::Invalid(_)) => "fixes_invalid",
                Some(Validity::NotFound) | None => "missing",
            },
        })
        .collect();
    v.sort_by_key(|a| a.prefix);
    v.dedup();
    v
}

#[derive(Debug, Clone, Serialize)]
pub struct LooseVrp {
    pub vrp: Vrp,
    /// Number of distinct prefixes this VRP authorises (saturating).
    pub authorised: u128,
    /// Announced prefixes of the AS inside what the VRP authorises.
    pub announced: Vec<Prefix>,
    /// Authorised but not announced: forged-origin sub-prefix hijack surface.
    pub unannounced: u128,
    /// Exact ROAs that would replace this VRP without the exposure.
    pub replace_with: Vec<Prefix>,
}

/// Prefixes authorised by a VRP: 2^(m-l+1) - 1, saturating.
pub fn authorised_count(v: &Vrp) -> u128 {
    let bits = u32::from(v.max_length - v.prefix.len()) + 1;
    1u128.checked_shl(bits).map_or(u128::MAX, |n| n - 1)
}

/// Flags VRPs of `asn` whose maxLength authorises prefixes the AS does not
/// announce (RFC 9319). VRPs with maxLength = prefix length are never loose.
pub fn audit_max_length(table: &VrpTable, asn: u32, announced: &[Prefix]) -> Vec<LooseVrp> {
    table
        .vrps()
        .iter()
        .filter(|v| v.asn == asn && v.max_length > v.prefix.len())
        .filter_map(|v| {
            let mut inside: Vec<Prefix> = announced
                .iter()
                .copied()
                .filter(|p| matches(v, p, asn) && v.prefix.covers(p))
                .collect();
            inside.sort_unstable();
            inside.dedup();
            let authorised = authorised_count(v);
            let unannounced = authorised.saturating_sub(inside.len() as u128);
            (unannounced > 0).then(|| LooseVrp {
                vrp: *v,
                authorised,
                replace_with: inside.clone(),
                announced: inside,
                unannounced,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn vrp(s: &str, m: u8, a: u32) -> Vrp {
        Vrp::new(p(s), m, a).unwrap()
    }

    #[test]
    fn suggestions() {
        let t = VrpTable::from_vrps([
            vrp("192.0.2.0/24", 24, 64500),
            vrp("198.51.100.0/24", 24, 64599),
        ]);
        let s = suggest(
            Some(&t),
            64500,
            &[
                p("198.51.100.0/24"),
                p("192.0.2.0/24"),
                p("203.0.113.0/24"),
                p("192.0.2.0/24"),
            ],
        );
        let st: Vec<_> = s
            .iter()
            .map(|s| (s.prefix.to_string(), s.max_length, s.status))
            .collect();
        assert_eq!(
            st,
            vec![
                ("192.0.2.0/24".into(), 24, "covered"),
                ("198.51.100.0/24".into(), 24, "fixes_invalid"),
                ("203.0.113.0/24".into(), 24, "missing"),
            ]
        );
        assert!(suggest(None, 1, &[p("192.0.2.0/24")])
            .iter()
            .all(|s| s.status == "missing"));
    }

    #[test]
    fn counts() {
        assert_eq!(authorised_count(&vrp("192.0.2.0/24", 24, 1)), 1);
        assert_eq!(authorised_count(&vrp("192.0.2.0/24", 25, 1)), 3);
        assert_eq!(authorised_count(&vrp("192.0.0.0/16", 24, 1)), 511);
        assert_eq!(authorised_count(&vrp("::/0", 128, 1)), u128::MAX);
    }

    #[test]
    fn looseness() {
        let t = VrpTable::from_vrps([
            vrp("192.0.2.0/24", 24, 64500),    // exact: never loose
            vrp("198.51.100.0/22", 24, 64500), // loose: only /22 announced
            vrp("203.0.113.0/24", 25, 64500),  // tight: all three announced
            vrp("198.18.0.0/15", 24, 64501),   // other AS
        ]);
        let ann = [
            p("198.51.100.0/22"),
            p("203.0.113.0/24"),
            p("203.0.113.0/25"),
            p("203.0.113.128/25"),
        ];
        let l = audit_max_length(&t, 64500, &ann);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].vrp, vrp("198.51.100.0/22", 24, 64500));
        assert_eq!(l[0].authorised, 7);
        assert_eq!(l[0].unannounced, 6);
        assert_eq!(l[0].replace_with, vec![p("198.51.100.0/22")]);
    }
}
