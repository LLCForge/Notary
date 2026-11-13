//! Validated ROA Payloads, ASPA records, the prefix trie that indexes them
//! and the JSON export loader.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::prefix::{Asn, Family, Prefix};

/// Upper bound for a JSON VRP export read from disk or over HTTP.
pub const MAX_JSON_BYTES: u64 = 512 * 1024 * 1024;
/// Upper bound for providers in one ASPA record (an RTR PDU holds ~16k).
pub const MAX_ASPA_PROVIDERS: usize = 16_384;

#[derive(Debug, thiserror::Error)]
pub enum VrpError {
    #[error("maxLength {max_len} is invalid for {prefix} (must be between {min} and {max})")]
    BadMaxLength {
        prefix: Prefix,
        max_len: u8,
        min: u8,
        max: u8,
    },
    #[error("ROA #{index}: {message}")]
    BadEntry { index: usize, message: String },
    #[error("invalid VRP JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vrp {
    pub prefix: Prefix,
    pub max_length: u8,
    pub asn: u32,
}

impl Vrp {
    pub fn new(prefix: Prefix, max_length: u8, asn: u32) -> Result<Self, VrpError> {
        let max = prefix.family().max_len();
        if max_length < prefix.len() || max_length > max {
            return Err(VrpError::BadMaxLength {
                prefix,
                max_len: max_length,
                min: prefix.len(),
                max,
            });
        }
        Ok(Vrp {
            prefix,
            max_length,
            asn,
        })
    }
}

/// Binary trie over prefix bits, stored in an arena so large VRP sets do
/// not need millions of individual heap boxes.
#[derive(Debug, Clone)]
pub struct Trie {
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, Default)]
struct Node {
    /// Arena index of the 0/1 child, 0 meaning "none" (index 0 is the root).
    children: [u32; 2],
    vrps: Vec<Vrp>,
}

impl Default for Trie {
    fn default() -> Self {
        Trie {
            nodes: vec![Node::default()],
        }
    }
}

impl Trie {
    pub fn insert(&mut self, vrp: Vrp) {
        let mut idx = 0usize;
        for i in 0..vrp.prefix.len() {
            let b = usize::from(vrp.prefix.bit(i));
            let next = self.nodes[idx].children[b];
            idx = if next == 0 {
                let new = self.nodes.len();
                self.nodes.push(Node::default());
                // shortcut: u32 arena indexes cap the trie at 4 billion nodes, far above any real VRP set.
                self.nodes[idx].children[b] = new as u32;
                new
            } else {
                next as usize
            };
        }
        self.nodes[idx].vrps.push(vrp);
    }

    /// All VRPs whose prefix covers `prefix` (equal or less specific).
    pub fn covering(&self, prefix: &Prefix) -> Vec<Vrp> {
        let mut out = Vec::new();
        let mut idx = 0usize;
        out.extend_from_slice(&self.nodes[0].vrps);
        for i in 0..prefix.len() {
            let next = self.nodes[idx].children[usize::from(prefix.bit(i))];
            if next == 0 {
                break;
            }
            idx = next as usize;
            out.extend_from_slice(&self.nodes[idx].vrps);
        }
        out
    }
}

/// One payload set as delivered by a source: VRPs, ASPA records (customer
/// AS -> sorted providers) and, when the source reports it, the expiry time
/// (Unix seconds) of each VRP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VrpData {
    pub vrps: Vec<Vrp>,
    pub aspas: BTreeMap<u32, Vec<u32>>,
    pub expires: HashMap<Vrp, i64>,
}

impl VrpData {
    pub fn from_vrps<I: IntoIterator<Item = Vrp>>(vrps: I) -> Self {
        let mut d = VrpData {
            vrps: vrps.into_iter().collect(),
            ..VrpData::default()
        };
        d.normalize();
        d
    }

    /// Sorts and de-duplicates VRPs and providers.
    pub fn normalize(&mut self) {
        self.vrps.sort_unstable();
        self.vrps.dedup();
        for p in self.aspas.values_mut() {
            p.sort_unstable();
            p.dedup();
        }
    }
}

/// Immutable VRP index; a new one is built for every update and swapped in.
#[derive(Debug, Clone, Default)]
pub struct VrpTable {
    v4: Trie,
    v6: Trie,
    v4_count: usize,
    v6_count: usize,
    data: VrpData,
}

impl VrpTable {
    pub fn from_vrps<I: IntoIterator<Item = Vrp>>(vrps: I) -> Self {
        Self::build(VrpData::from_vrps(vrps))
    }

    /// Indexes a payload set (normalised first).
    pub fn build(mut data: VrpData) -> Self {
        data.normalize();
        let mut t = VrpTable::default();
        for &vrp in &data.vrps {
            match vrp.prefix.family() {
                Family::V4 => {
                    t.v4.insert(vrp);
                    t.v4_count += 1;
                }
                Family::V6 => {
                    t.v6.insert(vrp);
                    t.v6_count += 1;
                }
            }
        }
        t.data = data;
        t
    }

    pub fn covering(&self, prefix: &Prefix) -> Vec<Vrp> {
        match prefix.family() {
            Family::V4 => self.v4.covering(prefix),
            Family::V6 => self.v6.covering(prefix),
        }
    }

    pub fn len(&self) -> usize {
        self.v4_count + self.v6_count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn v4_count(&self) -> usize {
        self.v4_count
    }

    pub fn v6_count(&self) -> usize {
        self.v6_count
    }

    /// All VRPs, sorted and de-duplicated.
    pub fn vrps(&self) -> &[Vrp] {
        &self.data.vrps
    }

    pub fn data(&self) -> &VrpData {
        &self.data
    }

    /// Providers attested by the ASPA record of `customer`, if any.
    pub fn aspa(&self, customer: u32) -> Option<&[u32]> {
        self.data.aspas.get(&customer).map(Vec::as_slice)
    }

    pub fn aspa_count(&self) -> usize {
        self.data.aspas.len()
    }

    /// Expiry (Unix seconds) of `vrp`, when the source reported one.
    pub fn expires(&self, vrp: &Vrp) -> Option<i64> {
        self.data.expires.get(vrp).copied()
    }
}

#[derive(Deserialize)]
struct JsonExport {
    roas: Vec<JsonRoa>,
    #[serde(default)]
    aspas: Vec<JsonAspa>,
}

#[derive(Deserialize)]
struct JsonRoa {
    prefix: String,
    #[serde(rename = "maxLength")]
    max_length: u8,
    asn: Asn,
    /// rpki-client: Unix time at which the ROA (or its chain) expires.
    #[serde(default)]
    expires: Option<i64>,
    /// Routinator `jsonext`: one entry per ROA that produced this VRP.
    #[serde(default)]
    source: Vec<JsonSource>,
}

#[derive(Deserialize)]
struct JsonSource {
    #[serde(default)]
    validity: Option<JsonValidity>,
    #[serde(default, rename = "chainValidity")]
    chain_validity: Option<JsonValidity>,
}

#[derive(Deserialize)]
struct JsonValidity {
    #[serde(rename = "notAfter")]
    not_after: String,
}

/// rpki-client writes `customer_asid`, Routinator `customer`.
#[derive(Deserialize)]
struct JsonAspa {
    #[serde(alias = "customer_asid")]
    customer: Asn,
    providers: Vec<Asn>,
}

impl JsonRoa {
    /// Latest moment this VRP stays valid: it disappears only once every
    /// ROA behind it has expired.
    fn expiry(&self) -> Option<i64> {
        let from_sources = self
            .source
            .iter()
            .filter_map(|s| s.chain_validity.as_ref().or(s.validity.as_ref()))
            .filter_map(|v| chrono::DateTime::parse_from_rfc3339(&v.not_after).ok())
            .map(|t| t.timestamp())
            .max();
        self.expires.into_iter().chain(from_sources).max()
    }
}

/// Parses a Routinator / rpki-client style `{"roas": [...]}` export.
/// Duplicate entries (same prefix, maxLength, ASN under several trust
/// anchors) are collapsed.
pub fn parse_json(bytes: &[u8]) -> Result<Vec<Vrp>, VrpError> {
    Ok(parse_json_data(bytes)?.vrps)
}

/// Like [`parse_json`], keeping ASPA records (`aspas`) and expiry data
/// (rpki-client `expires`, Routinator `jsonext` `source[].chainValidity`).
pub fn parse_json_data(bytes: &[u8]) -> Result<VrpData, VrpError> {
    let export: JsonExport = serde_json::from_slice(bytes)?;
    let mut data = VrpData::default();
    let mut out = Vec::with_capacity(export.roas.len());
    for (index, roa) in export.roas.into_iter().enumerate() {
        let prefix: Prefix = roa.prefix.parse().map_err(|e| VrpError::BadEntry {
            index,
            message: format!("prefix {:?}: {e}", roa.prefix),
        })?;
        let vrp = Vrp::new(prefix, roa.max_length, roa.asn.0).map_err(|e| VrpError::BadEntry {
            index,
            message: e.to_string(),
        })?;
        if let Some(exp) = roa.expiry() {
            let e = data.expires.entry(vrp).or_insert(exp);
            *e = (*e).max(exp);
        }
        out.push(vrp);
    }
    for (index, a) in export.aspas.into_iter().enumerate() {
        let providers = data.aspas.entry(a.customer.0).or_default();
        providers.extend(a.providers.iter().map(|p| p.0));
        if providers.len() > MAX_ASPA_PROVIDERS {
            return Err(VrpError::BadEntry {
                index,
                message: format!("ASPA for AS{} lists too many providers", a.customer.0),
            });
        }
    }
    data.vrps = out;
    data.normalize();
    Ok(data)
}

/// Loads a JSON export (VRPs, ASPA records, expiry data) from a local path
/// or an `http(s)://` URL.
pub async fn load_json_data(source: &str, client: &reqwest::Client) -> anyhow::Result<VrpData> {
    let bytes = if source.starts_with("https://") || source.starts_with("http://") {
        crate::http::get_limited(client, source, MAX_JSON_BYTES).await?
    } else {
        let path = Path::new(source);
        let meta = tokio::fs::metadata(path)
            .await
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        if meta.len() > MAX_JSON_BYTES {
            anyhow::bail!(
                "{} is larger than the {} byte limit",
                path.display(),
                MAX_JSON_BYTES
            );
        }
        tokio::fs::read(path).await?
    };
    Ok(parse_json_data(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp(p: &str, max: u8, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), max, asn).unwrap()
    }

    #[test]
    fn vrp_max_length_bounds() {
        assert!(Vrp::new("192.0.2.0/24".parse().unwrap(), 23, 64500).is_err());
        assert!(Vrp::new("192.0.2.0/24".parse().unwrap(), 33, 64500).is_err());
        assert!(Vrp::new("192.0.2.0/24".parse().unwrap(), 24, 64500).is_ok());
        assert!(Vrp::new("2001:db8::/32".parse().unwrap(), 128, 64500).is_ok());
    }

    #[test]
    fn trie_covering() {
        let t = VrpTable::from_vrps([
            vrp("198.51.100.0/22", 24, 64500),
            vrp("198.51.100.0/24", 24, 64501),
            vrp("198.51.101.0/24", 24, 64502),
            vrp("203.0.113.0/24", 24, 64503),
            vrp("2001:db8::/32", 48, 64504),
        ]);
        assert_eq!(t.len(), 5);
        assert_eq!(t.v4_count(), 4);
        assert_eq!(t.v6_count(), 1);

        let mut c = t.covering(&"198.51.100.0/24".parse().unwrap());
        c.sort();
        assert_eq!(
            c,
            vec![
                vrp("198.51.100.0/22", 24, 64500),
                vrp("198.51.100.0/24", 24, 64501)
            ]
        );
        // Unrelated space.
        assert!(t.covering(&"192.0.2.0/24".parse().unwrap()).is_empty());
        // Families are kept apart.
        assert_eq!(t.covering(&"2001:db8:1::/48".parse().unwrap()).len(), 1);
        assert!(t.covering(&"2001:db9::/32".parse().unwrap()).is_empty());
    }

    #[test]
    fn trie_default_route_vrp() {
        let t = VrpTable::from_vrps([vrp("0.0.0.0/0", 32, 64500)]);
        assert_eq!(t.covering(&"192.0.2.1/32".parse().unwrap()).len(), 1);
        assert_eq!(t.covering(&"0.0.0.0/0".parse().unwrap()).len(), 1);
        assert!(t.covering(&"::/0".parse().unwrap()).is_empty());
    }

    #[test]
    fn duplicate_vrps_are_counted_once() {
        let t = VrpTable::from_vrps([vrp("192.0.2.0/24", 24, 1), vrp("192.0.2.0/24", 24, 1)]);
        assert_eq!(t.len(), 1);
        assert_eq!(t.vrps().len(), 1);
    }

    #[test]
    fn json_parses_both_asn_forms_and_dedups() {
        let json = br#"{"metadata":{"generated":1},"roas":[
            {"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS64500","ta":"ripe"},
            {"prefix":"192.0.2.0/24","maxLength":24,"asn":64500,"ta":"arin"},
            {"prefix":"2001:db8::/32","maxLength":48,"asn":64501}
        ]}"#;
        let v = parse_json(json).unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&vrp("192.0.2.0/24", 24, 64500)));
        assert!(v.contains(&vrp("2001:db8::/32", 48, 64501)));
    }

    #[test]
    fn json_rejects_bad_entries() {
        let bad_prefix = br#"{"roas":[{"prefix":"192.0.2.1/24","maxLength":24,"asn":64500}]}"#;
        assert!(matches!(
            parse_json(bad_prefix),
            Err(VrpError::BadEntry { index: 0, .. })
        ));
        let bad_max = br#"{"roas":[{"prefix":"192.0.2.0/24","maxLength":20,"asn":64500}]}"#;
        assert!(parse_json(bad_max).is_err());
        let bad_asn = br#"{"roas":[{"prefix":"192.0.2.0/24","maxLength":24,"asn":"ASx"}]}"#;
        assert!(parse_json(bad_asn).is_err());
        assert!(parse_json(br#"{"vrps":[]}"#).is_err());
        assert!(parse_json(b"not json").is_err());
        assert!(parse_json(br#"{"roas":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn json_expiry_and_aspas() {
        let json = br#"{"roas":[
            {"prefix":"192.0.2.0/24","maxLength":24,"asn":64500,"expires":1700000000},
            {"prefix":"192.0.2.0/24","maxLength":24,"asn":64500,"expires":1800000000},
            {"prefix":"198.51.100.0/24","maxLength":24,"asn":"AS64501","source":[
              {"type":"roa","validity":{"notBefore":"2026-01-01T00:00:00Z","notAfter":"2027-01-01T00:00:00Z"},
               "chainValidity":{"notBefore":"2026-01-01T00:00:00Z","notAfter":"2026-06-01T00:00:00Z"}}]},
            {"prefix":"203.0.113.0/24","maxLength":24,"asn":64502}
          ],
          "aspas":[{"customer_asid":64500,"expires":1,"providers":[64511,64510,64511]},
                   {"customer":"AS64501","providers":["AS64512"]}]}"#;
        let d = parse_json_data(json).unwrap();
        assert_eq!(d.vrps.len(), 3);
        assert_eq!(d.expires[&vrp("192.0.2.0/24", 24, 64500)], 1_800_000_000);
        assert_eq!(
            d.expires[&vrp("198.51.100.0/24", 24, 64501)],
            chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                .unwrap()
                .timestamp()
        );
        assert!(!d.expires.contains_key(&vrp("203.0.113.0/24", 24, 64502)));
        assert_eq!(d.aspas[&64500], vec![64510, 64511]);
        let t = VrpTable::build(d);
        assert_eq!(t.aspa(64501), Some(&[64512][..]));
        assert_eq!(t.aspa(64502), None);
        assert_eq!(t.aspa_count(), 2);
    }

    #[tokio::test]
    async fn example_fixture_loads() {
        let client = reqwest::Client::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/vrps.json");
        let v = load_json_data(path, &client).await.unwrap();
        assert!(!v.vrps.is_empty());
    }
}
