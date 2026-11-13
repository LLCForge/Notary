//! Where "prefixes originated by AS X" come from: RIPEstat
//! `announced-prefixes`, the Pathology API (`/v1/origins`, your own
//! routers' view) and the bgp.tools table dump.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::Duration;

use anyhow::{bail, Context};
use serde::Deserialize;

use crate::prefix::Prefix;

const RIPESTAT_URL: &str = "https://stat.ripe.net/data/announced-prefixes/data.json";
/// Upper bound for one RIPEstat / Pathology response.
const RESPONSE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const BGPTOOLS_URL: &str = "https://bgp.tools/table.jsonl";
/// bgp.tools full table (about 1.5M lines); generous ceiling.
const BGPTOOLS_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const BGPTOOLS_MAX_LINE: usize = 4096;
/// bgp.tools asks clients not to fetch more often than this.
pub const BGPTOOLS_MIN_INTERVAL_SECS: u64 = 1800;
/// Cross-tool calls are time-boxed.
const PATHOLOGY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixSource {
    RipeStat,
    /// Pathology read-only API base URL plus optional bearer token.
    Pathology {
        url: String,
        token: Option<String>,
    },
    /// bgp.tools requires an identifying User-Agent with a contact.
    BgpTools {
        user_agent: String,
    },
}

impl fmt::Display for PrefixSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrefixSource::RipeStat => f.write_str("ripestat"),
            PrefixSource::Pathology { url, .. } => write!(f, "pathology({url})"),
            PrefixSource::BgpTools { .. } => f.write_str("bgp.tools"),
        }
    }
}

impl PrefixSource {
    /// CLI form: `ripestat`, `bgptools` (needs `user_agent`) or a Pathology
    /// base URL `http(s)://host:port` (token from `PATHOLOGY_API_TOKEN`).
    pub fn from_cli(s: &str, user_agent: Option<&str>) -> anyhow::Result<Self> {
        match s {
            "ripestat" => Ok(PrefixSource::RipeStat),
            "bgptools" | "bgp.tools" => Ok(PrefixSource::BgpTools {
                user_agent: validate_user_agent(user_agent.unwrap_or_default())?,
            }),
            url if url.starts_with("http://") || url.starts_with("https://") => {
                Ok(PrefixSource::Pathology {
                    url: url.trim_end_matches('/').to_string(),
                    token: std::env::var("PATHOLOGY_API_TOKEN")
                        .ok()
                        .filter(|t| !t.trim().is_empty()),
                })
            }
            other => {
                bail!("unknown prefix source {other:?} (ripestat, bgptools or a Pathology URL)")
            }
        }
    }
}

/// bgp.tools rejects generic agents; insist on something with a contact.
pub fn validate_user_agent(ua: &str) -> anyhow::Result<String> {
    let ua = ua.trim();
    if ua.len() < 8
        || ua.len() > 200
        || !ua.contains(['@', '/'])
        || ua.chars().any(char::is_control)
    {
        bail!(
            "bgp.tools needs a User-Agent naming you and a contact, e.g. \"example-noc notary - noc@example.net\""
        );
    }
    Ok(ua.to_string())
}

#[derive(Deserialize)]
struct RipeStat {
    data: RipeStatData,
}

#[derive(Deserialize)]
struct RipeStatData {
    prefixes: Vec<RipeStatPrefix>,
}

#[derive(Deserialize)]
struct RipeStatPrefix {
    prefix: String,
}

/// Extracts prefixes from a RIPEstat `announced-prefixes` response,
/// skipping unparsable entries and keeping at most `max`.
pub fn parse_ripestat(body: &[u8], max: usize) -> anyhow::Result<(Vec<Prefix>, bool)> {
    let r: RipeStat = serde_json::from_slice(body).context("parsing RIPEstat response")?;
    let items = r.data.prefixes.iter().map(|p| p.prefix.as_str());
    Ok(collect(items, max))
}

#[derive(Deserialize)]
struct Origins {
    prefixes: Vec<String>,
}

/// Parses Pathology `GET /v1/origins?asn=N` → `{"prefixes": [...]}`.
pub fn parse_origins(body: &[u8], max: usize) -> anyhow::Result<(Vec<Prefix>, bool)> {
    let r: Origins = serde_json::from_slice(body).context("parsing Pathology /v1/origins")?;
    Ok(collect(r.prefixes.iter().map(String::as_str), max))
}

fn collect<'a>(items: impl Iterator<Item = &'a str>, max: usize) -> (Vec<Prefix>, bool) {
    let mut set = BTreeSet::new();
    let mut truncated = false;
    for p in items {
        if let Ok(p) = p.parse::<Prefix>() {
            if set.len() >= max && !set.contains(&p) {
                truncated = true;
                break;
            }
            set.insert(p);
        }
    }
    (set.into_iter().collect(), truncated)
}

#[derive(Deserialize)]
struct BgpToolsLine {
    #[serde(rename = "CIDR")]
    cidr: String,
    #[serde(rename = "ASN")]
    asn: u32,
}

/// Incremental parser for the bgp.tools `table.jsonl` dump, keeping only
/// the origins in `wanted`.
pub struct BgpToolsParser<'a> {
    wanted: &'a BTreeSet<u32>,
    partial: Vec<u8>,
    pub out: HashMap<u32, BTreeSet<Prefix>>,
}

impl<'a> BgpToolsParser<'a> {
    pub fn new(wanted: &'a BTreeSet<u32>) -> Self {
        BgpToolsParser {
            wanted,
            partial: Vec::new(),
            out: HashMap::new(),
        }
    }

    pub fn feed(&mut self, mut chunk: &[u8]) {
        while let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
            if self.partial.len() + nl <= BGPTOOLS_MAX_LINE {
                self.partial.extend_from_slice(&chunk[..nl]);
                let line = std::mem::take(&mut self.partial);
                self.line(&line);
            }
            self.partial.clear();
            chunk = &chunk[nl + 1..];
        }
        if self.partial.len() + chunk.len() <= BGPTOOLS_MAX_LINE {
            self.partial.extend_from_slice(chunk);
        } else {
            // Oversized line: an over-long marker keeps it dropped until its newline.
            self.partial.clear();
            self.partial.resize(BGPTOOLS_MAX_LINE + 1, b' ');
        }
    }

    pub fn finish(mut self) -> HashMap<u32, BTreeSet<Prefix>> {
        let line = std::mem::take(&mut self.partial);
        if line.len() <= BGPTOOLS_MAX_LINE {
            self.line(&line);
        }
        self.out
    }

    fn line(&mut self, line: &[u8]) {
        let Ok(l) = serde_json::from_slice::<BgpToolsLine>(line) else {
            return;
        };
        if self.wanted.contains(&l.asn) {
            if let Ok(p) = l.cidr.parse() {
                self.out.entry(l.asn).or_default().insert(p);
            }
        }
    }
}

async fn get(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    limit: u64,
    timeout: Option<Duration>,
) -> anyhow::Result<Vec<u8>> {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    if let Some(t) = timeout {
        req = req.timeout(t);
    }
    crate::http::read_limited(
        req.send().await.with_context(|| format!("GET {url}"))?,
        url,
        limit,
    )
    .await
}

/// Fetches the prefixes each AS in `asns` originates, per `source`. ASes
/// without data map to an empty list. The bool flags truncation at `max`.
pub async fn fetch(
    client: &reqwest::Client,
    source: &PrefixSource,
    asns: &[u32],
    max: usize,
) -> anyhow::Result<HashMap<u32, (Vec<Prefix>, bool)>> {
    let mut out = HashMap::new();
    match source {
        PrefixSource::RipeStat => {
            for &asn in asns {
                let url = format!("{RIPESTAT_URL}?resource=AS{asn}");
                let body = get(client, &url, None, RESPONSE_MAX_BYTES, None).await?;
                out.insert(asn, parse_ripestat(&body, max)?);
            }
        }
        PrefixSource::Pathology { url, token } => {
            for &asn in asns {
                let u = format!("{url}/v1/origins?asn={asn}");
                let body = get(
                    client,
                    &u,
                    token.as_deref(),
                    RESPONSE_MAX_BYTES,
                    Some(PATHOLOGY_TIMEOUT),
                )
                .await?;
                out.insert(asn, parse_origins(&body, max)?);
            }
        }
        PrefixSource::BgpTools { user_agent } => {
            let wanted: BTreeSet<u32> = asns.iter().copied().collect();
            let mut resp = client
                .get(BGPTOOLS_URL)
                .header(reqwest::header::USER_AGENT, user_agent.as_str())
                .send()
                .await
                .context("GET bgp.tools table")?;
            if !resp.status().is_success() {
                bail!("GET {BGPTOOLS_URL}: HTTP {}", resp.status());
            }
            let mut parser = BgpToolsParser::new(&wanted);
            let mut total = 0u64;
            while let Some(chunk) = resp.chunk().await.context("reading bgp.tools table")? {
                total += chunk.len() as u64;
                if total > BGPTOOLS_MAX_BYTES {
                    bail!("bgp.tools table larger than {BGPTOOLS_MAX_BYTES} bytes");
                }
                parser.feed(&chunk);
            }
            let mut found = parser.finish();
            for &asn in asns {
                let set = found.remove(&asn).unwrap_or_default();
                let truncated = set.len() > max;
                out.insert(asn, (set.into_iter().take(max).collect(), truncated));
            }
        }
    }
    for &asn in asns {
        if out.get(&asn).is_some_and(|(_, t)| *t) {
            tracing::warn!(asn, max, %source, "prefix list truncated");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripestat_parsing() {
        let body = br#"{"status":"ok","data":{"resource":"64501","prefixes":[
            {"prefix":"198.51.100.0/24","timelines":[]},
            {"prefix":"2001:db8::/32","timelines":[]},
            {"prefix":"garbage","timelines":[]},
            {"prefix":"192.0.2.0/24","timelines":[]}
        ]}}"#;
        let (p, truncated) = parse_ripestat(body, 10).unwrap();
        assert_eq!(p.len(), 3);
        assert!(!truncated);
        let (p, truncated) = parse_ripestat(body, 1).unwrap();
        assert_eq!(p.len(), 1);
        assert!(truncated);
        assert!(parse_ripestat(b"{}", 10).is_err());
    }

    #[test]
    fn origins_parsing() {
        let (p, t) = parse_origins(
            br#"{"prefixes":["198.51.100.0/24","198.51.100.0/24","bad","2001:db8::/48"]}"#,
            10,
        )
        .unwrap();
        assert_eq!(p.len(), 2);
        assert!(!t);
        assert!(parse_origins(br#"{"events":[]}"#, 10).is_err());
    }

    #[test]
    fn bgptools_streaming() {
        let wanted: BTreeSet<u32> = [64500, 64501].into();
        let mut parser = BgpToolsParser::new(&wanted);
        let data = b"{\"CIDR\":\"192.0.2.0/24\",\"ASN\":64500,\"Hits\":500}\n\
            {\"CIDR\":\"198.51.100.0/24\",\"ASN\":64599,\"Hits\":3}\n\
            not json\n\
            {\"CIDR\":\"2001:db8::/48\",\"ASN\":64501,\"Hits\":12}\n";
        // Feed in awkward chunk sizes to exercise line reassembly.
        for c in data.chunks(7) {
            parser.feed(c);
        }
        let mut long = vec![b'x'; BGPTOOLS_MAX_LINE * 3];
        long.push(b'\n');
        parser.feed(&long);
        parser.feed(b"{\"CIDR\":\"203.0.113.0/24\",\"ASN\":64500,\"Hits\":1}\n");
        let out = parser.finish();
        assert_eq!(out[&64500].len(), 2);
        assert_eq!(out[&64501].len(), 1);
        assert!(!out.contains_key(&64599));
    }

    #[test]
    fn cli_sources() {
        assert_eq!(
            PrefixSource::from_cli("ripestat", None).unwrap(),
            PrefixSource::RipeStat
        );
        assert!(PrefixSource::from_cli("bgptools", None).is_err());
        assert!(PrefixSource::from_cli("bgptools", Some("example-noc - noc@example.net")).is_ok());
        assert!(matches!(
            PrefixSource::from_cli("http://127.0.0.1:8180/", None).unwrap(),
            PrefixSource::Pathology { url, .. } if url == "http://127.0.0.1:8180"
        ));
        assert!(PrefixSource::from_cli("ftp://x", None).is_err());
    }
}
