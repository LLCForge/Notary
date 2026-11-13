//! SLURM (RFC 8416): local filters and assertions applied on top of the
//! validated payloads from the cache / JSON export.

use std::path::Path;

use anyhow::{bail, Context};
use serde::Deserialize;

use crate::prefix::Prefix;
use crate::vrp::{Vrp, VrpData};

/// SLURM files are hand-written; anything larger is a mistake.
const MAX_SLURM_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SlurmFile {
    slurm_version: u32,
    validation_output_filters: Filters,
    locally_added_assertions: Assertions,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Filters {
    prefix_filters: Vec<PrefixFilter>,
    #[allow(dead_code)]
    bgpsec_filters: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrefixFilter {
    prefix: Option<Prefix>,
    asn: Option<u32>,
    #[allow(dead_code)]
    comment: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assertions {
    prefix_assertions: Vec<PrefixAssertion>,
    #[allow(dead_code)]
    bgpsec_assertions: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrefixAssertion {
    asn: u32,
    prefix: Prefix,
    max_prefix_length: Option<u8>,
    #[allow(dead_code)]
    comment: Option<String>,
}

/// Parsed and merged SLURM rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Slurm {
    /// `(prefix, asn)`; at least one is set.
    filters: Vec<(Option<Prefix>, Option<u32>)>,
    assertions: Vec<Vrp>,
}

impl Slurm {
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Slurm> {
        let f: SlurmFile = serde_json::from_slice(bytes).context("invalid SLURM JSON")?;
        if f.slurm_version != 1 {
            bail!("unsupported slurmVersion {}", f.slurm_version);
        }
        let mut s = Slurm::default();
        for (i, pf) in f
            .validation_output_filters
            .prefix_filters
            .into_iter()
            .enumerate()
        {
            if pf.prefix.is_none() && pf.asn.is_none() {
                bail!("prefixFilters[{i}]: needs a prefix, an asn or both");
            }
            s.filters.push((pf.prefix, pf.asn));
        }
        for (i, a) in f
            .locally_added_assertions
            .prefix_assertions
            .into_iter()
            .enumerate()
        {
            let max = a.max_prefix_length.unwrap_or(a.prefix.len());
            let vrp =
                Vrp::new(a.prefix, max, a.asn).with_context(|| format!("prefixAssertions[{i}]"))?;
            s.assertions.push(vrp);
        }
        Ok(s)
    }

    /// Loads and merges several files (empty list: `None`).
    pub fn load(paths: &[impl AsRef<Path>]) -> anyhow::Result<Option<Slurm>> {
        if paths.is_empty() {
            return Ok(None);
        }
        let mut all = Slurm::default();
        for p in paths {
            let p = p.as_ref();
            let meta = std::fs::metadata(p).with_context(|| format!("reading {}", p.display()))?;
            if meta.len() > MAX_SLURM_BYTES {
                bail!("{} is larger than {MAX_SLURM_BYTES} bytes", p.display());
            }
            let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            let s = Slurm::parse(&bytes).with_context(|| format!("SLURM file {}", p.display()))?;
            all.filters.extend(s.filters);
            all.assertions.extend(s.assertions);
        }
        Ok(Some(all))
    }

    fn filtered(&self, v: &Vrp) -> bool {
        self.filters
            .iter()
            .any(|(p, a)| p.is_none_or(|p| p.covers(&v.prefix)) && a.is_none_or(|a| a == v.asn))
    }

    /// Removes filtered VRPs, then adds assertions (RFC 8416 section 4.2).
    /// Returns `(filtered, asserted)` counts.
    pub fn apply(&self, data: &mut VrpData) -> (usize, usize) {
        let before = data.vrps.len();
        data.vrps.retain(|v| !self.filtered(v));
        let filtered = before - data.vrps.len();
        data.expires.retain(|v, _| !self.filtered(v));
        data.vrps.extend_from_slice(&self.assertions);
        data.normalize();
        (filtered, self.assertions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp(p: &str, max: u8, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), max, asn).unwrap()
    }

    const RFC_EXAMPLE: &str = r#"{
      "slurmVersion": 1,
      "validationOutputFilters": {
        "prefixFilters": [
          {"prefix": "192.0.2.0/24", "comment": "All VRPs encompassed by prefix"},
          {"asn": 64496, "comment": "All VRPs matching ASN"},
          {"prefix": "198.51.100.0/24", "asn": 64497, "comment": "All VRPs encompassed by prefix, matching ASN"}
        ],
        "bgpsecFilters": []
      },
      "locallyAddedAssertions": {
        "prefixAssertions": [
          {"asn": 64496, "prefix": "198.51.100.0/24", "comment": "My other important route"},
          {"asn": 64496, "prefix": "2001:db8::/32", "maxPrefixLength": 48, "comment": "My other important de-aggregated routes"}
        ],
        "bgpsecAssertions": []
      }
    }"#;

    #[test]
    fn rfc8416_example() {
        let s = Slurm::parse(RFC_EXAMPLE.as_bytes()).unwrap();
        let mut d = VrpData::from_vrps([
            vrp("192.0.2.0/25", 25, 64510),    // under filtered prefix
            vrp("203.0.113.0/24", 24, 64496),  // filtered ASN
            vrp("198.51.100.0/24", 24, 64497), // prefix+ASN filter
            vrp("198.51.100.0/24", 24, 64498), // survives (other ASN)
            vrp("192.0.0.0/16", 24, 64511),    // less specific than filter: survives
        ]);
        let (f, a) = s.apply(&mut d);
        assert_eq!((f, a), (3, 2));
        assert_eq!(
            d.vrps,
            vec![
                vrp("192.0.0.0/16", 24, 64511),
                vrp("198.51.100.0/24", 24, 64496),
                vrp("198.51.100.0/24", 24, 64498),
                vrp("2001:db8::/32", 48, 64496),
            ]
        );
    }

    #[test]
    fn rejects_bad_files() {
        let empty_filter = RFC_EXAMPLE.replace(
            r#"{"asn": 64496, "comment": "All VRPs matching ASN"}"#,
            "{}",
        );
        assert!(Slurm::parse(empty_filter.as_bytes()).is_err());
        assert!(Slurm::parse(
            RFC_EXAMPLE
                .replace("\"slurmVersion\": 1", "\"slurmVersion\": 2")
                .as_bytes()
        )
        .is_err());
        assert!(Slurm::parse(
            RFC_EXAMPLE
                .replace("\"maxPrefixLength\": 48", "\"maxPrefixLength\": 16")
                .as_bytes()
        )
        .is_err());
        assert!(Slurm::parse(b"{}").is_err());
        assert!(Slurm::load(&["/nonexistent/slurm.json"]).is_err());
        assert_eq!(Slurm::load(&[] as &[&str]).unwrap(), None);
    }
}
