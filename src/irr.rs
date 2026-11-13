//! IRR consistency: route/route6 objects for an origin AS (RIPE DB REST or
//! any IRR whois server) compared with the ROAs for that AS.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::prefix::Prefix;
use crate::validator::{validate, Validity};
use crate::vrp::VrpTable;

const RIPE_REST: &str = "https://rest.db.ripe.net/search.json";
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const WHOIS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrrSource {
    /// RIPE Database REST API (`source=RIPE`).
    RipeRest,
    /// Whois server `host[:port]`, queried with `-i origin ASn`.
    Whois(String),
}

impl IrrSource {
    pub fn parse(s: &str) -> anyhow::Result<IrrSource> {
        if s == "ripe" {
            return Ok(IrrSource::RipeRest);
        }
        let host = s.strip_prefix("whois://").unwrap_or(s);
        if host.is_empty() || host.len() > 255 || host.contains(['/', ' ', '@']) {
            bail!("IRR source must be \"ripe\" or whois://host[:port]");
        }
        let host = if host.contains(':') && !host.ends_with(']') {
            host.to_string()
        } else {
            format!("{host}:43")
        };
        Ok(IrrSource::Whois(host))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RouteObject {
    pub prefix: Prefix,
    pub origin: u32,
}

#[derive(Deserialize)]
struct RestResponse {
    objects: Option<RestObjects>,
}

#[derive(Deserialize)]
struct RestObjects {
    object: Vec<RestObject>,
}

#[derive(Deserialize)]
struct RestObject {
    #[serde(rename = "type")]
    kind: String,
    attributes: RestAttributes,
}

#[derive(Deserialize)]
struct RestAttributes {
    attribute: Vec<RestAttribute>,
}

#[derive(Deserialize)]
struct RestAttribute {
    name: String,
    value: String,
}

/// Parses a RIPE DB REST search response into route objects for `origin`.
pub fn parse_ripe_rest(body: &[u8], origin: u32) -> anyhow::Result<Vec<RouteObject>> {
    let r: RestResponse = serde_json::from_slice(body).context("parsing RIPE DB response")?;
    let mut out = BTreeSet::new();
    for o in r.objects.map(|o| o.object).unwrap_or_default() {
        if o.kind != "route" && o.kind != "route6" {
            continue;
        }
        let attr = |n: &str| {
            o.attributes
                .attribute
                .iter()
                .find(|a| a.name == n)
                .map(|a| a.value.trim().to_string())
        };
        let (Some(p), Some(a)) = (attr(&o.kind), attr("origin")) else {
            continue;
        };
        if let (Ok(prefix), Ok(asn)) = (p.parse(), crate::prefix::parse_asn(&a)) {
            if asn == origin {
                out.insert(RouteObject {
                    prefix,
                    origin: asn,
                });
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// Parses RPSL text (whois output) into route objects for `origin`.
pub fn parse_rpsl(text: &str, origin: u32) -> Vec<RouteObject> {
    let mut out = BTreeSet::new();
    for obj in text.split("\n\n") {
        let mut prefix = None;
        let mut asn = None;
        for line in obj.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            match k.trim() {
                "route" | "route6" if prefix.is_none() => prefix = v.trim().parse::<Prefix>().ok(),
                "origin" => asn = crate::prefix::parse_asn(v.trim()).ok(),
                _ => {}
            }
        }
        if let (Some(prefix), Some(a)) = (prefix, asn) {
            if a == origin {
                out.insert(RouteObject { prefix, origin: a });
            }
        }
    }
    out.into_iter().collect()
}

pub async fn fetch(
    client: &reqwest::Client,
    source: &IrrSource,
    origin: u32,
) -> anyhow::Result<Vec<RouteObject>> {
    match source {
        IrrSource::RipeRest => {
            let url = format!(
                "{RIPE_REST}?inverse-attribute=origin&type-filter=route&type-filter=route6\
                 &query-string=AS{origin}&flags=no-referenced&flags=no-irt&source=RIPE"
            );
            let resp = client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .context("RIPE DB query")?;
            // "No entries found" is a 404 with an error body.
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(Vec::new());
            }
            let body = crate::http::read_limited(resp, &url, MAX_BYTES).await?;
            parse_ripe_rest(&body, origin)
        }
        IrrSource::Whois(host) => {
            let text =
                tokio::time::timeout(WHOIS_TIMEOUT, whois(host, &format!("-i origin AS{origin}")))
                    .await
                    .map_err(|_| anyhow!("whois {host} timed out"))??;
            Ok(parse_rpsl(&text, origin))
        }
    }
}

async fn whois(host: &str, query: &str) -> anyhow::Result<String> {
    let mut s = tokio::net::TcpStream::connect(host)
        .await
        .with_context(|| format!("connecting to whois {host}"))?;
    s.write_all(format!("{query}\r\n").as_bytes()).await?;
    let mut buf = Vec::new();
    (&mut s).take(MAX_BYTES + 1).read_to_end(&mut buf).await?;
    if buf.len() as u64 > MAX_BYTES {
        bail!("whois response larger than {MAX_BYTES} bytes");
    }
    // CRLF -> LF so object separation by blank lines works.
    Ok(String::from_utf8_lossy(&buf).replace("\r\n", "\n"))
}

#[derive(Debug, Clone, Serialize)]
pub struct IrrFinding {
    pub prefix: Prefix,
    pub origin: u32,
    /// `route_object_rpki_invalid`, `route_object_rpki_not_found` or
    /// `roa_without_route_object`.
    pub issue: &'static str,
    pub detail: String,
}

/// Compares route objects with the ROAs of `origin`.
pub fn compare(table: &VrpTable, objects: &[RouteObject], origin: u32) -> Vec<IrrFinding> {
    let mut out = Vec::new();
    for o in objects {
        let v = validate(table, &o.prefix, o.origin);
        let issue = match v.validity {
            Validity::Valid => continue,
            Validity::Invalid(_) => "route_object_rpki_invalid",
            Validity::NotFound => "route_object_rpki_not_found",
        };
        out.push(IrrFinding {
            prefix: o.prefix,
            origin: o.origin,
            issue,
            detail: v.validity.to_string(),
        });
    }
    let objs: BTreeSet<Prefix> = objects.iter().map(|o| o.prefix).collect();
    for vrp in table.vrps().iter().filter(|v| v.asn == origin) {
        // A ROA is backed when some route object lies inside what it authorises.
        let backed = objs
            .iter()
            .any(|p| vrp.prefix.covers(p) && p.len() <= vrp.max_length);
        if !backed {
            out.push(IrrFinding {
                prefix: vrp.prefix,
                origin,
                issue: "roa_without_route_object",
                detail: format!("ROA max /{} has no route/route6 object", vrp.max_length),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrp::Vrp;

    #[test]
    fn ripe_rest() {
        let body = br#"{"objects":{"object":[
          {"type":"route","link":{},"source":{"id":"ripe"},
           "primary-key":{"attribute":[{"name":"route","value":"192.0.2.0/24"},{"name":"origin","value":"AS64500"}]},
           "attributes":{"attribute":[{"name":"route","value":"192.0.2.0/24"},{"name":"descr","value":"x"},{"name":"origin","value":"AS64500"}]}},
          {"type":"route6","attributes":{"attribute":[{"name":"route6","value":"2001:db8::/32"},{"name":"origin","value":"AS64500"}]}},
          {"type":"route","attributes":{"attribute":[{"name":"route","value":"198.51.100.0/24"},{"name":"origin","value":"AS64599"}]}},
          {"type":"aut-num","attributes":{"attribute":[{"name":"aut-num","value":"AS64500"}]}}
        ]}}"#;
        let r = parse_ripe_rest(body, 64500).unwrap();
        assert_eq!(r.len(), 2);
        assert!(parse_ripe_rest(br#"{"errormessages":{}}"#, 64500)
            .unwrap()
            .is_empty());
        assert!(parse_ripe_rest(b"nope", 1).is_err());
    }

    #[test]
    fn rpsl() {
        let text = "route:          192.0.2.0/24\ndescr:          x\norigin:         AS64500\nsource:         RADB\n\n\
                    route6:         2001:db8::/32\norigin:         AS64500\n\n\
                    route:          198.51.100.0/24\norigin:         AS64599\n\n%  comment\n";
        let r = parse_rpsl(text, 64500);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].prefix.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn sources() {
        assert_eq!(IrrSource::parse("ripe").unwrap(), IrrSource::RipeRest);
        assert_eq!(
            IrrSource::parse("whois://whois.example.net").unwrap(),
            IrrSource::Whois("whois.example.net:43".into())
        );
        assert_eq!(
            IrrSource::parse("whois.example.net:4343").unwrap(),
            IrrSource::Whois("whois.example.net:4343".into())
        );
        assert!(IrrSource::parse("http://x/y").is_err());
    }

    #[test]
    fn comparison() {
        let v = |p: &str, m, a| Vrp::new(p.parse().unwrap(), m, a).unwrap();
        let t = VrpTable::from_vrps([
            v("192.0.2.0/24", 24, 64500),
            v("198.51.100.0/24", 24, 64599),
            v("203.0.113.0/24", 24, 64500),
        ]);
        let objs = [
            RouteObject {
                prefix: "192.0.2.0/24".parse().unwrap(),
                origin: 64500,
            },
            RouteObject {
                prefix: "198.51.100.0/24".parse().unwrap(),
                origin: 64500,
            },
            RouteObject {
                prefix: "2001:db8::/32".parse().unwrap(),
                origin: 64500,
            },
        ];
        let f = compare(&t, &objs, 64500);
        let issues: Vec<_> = f.iter().map(|f| (f.prefix.to_string(), f.issue)).collect();
        assert_eq!(
            issues,
            vec![
                ("198.51.100.0/24".to_string(), "route_object_rpki_invalid"),
                ("2001:db8::/32".to_string(), "route_object_rpki_not_found"),
                ("203.0.113.0/24".to_string(), "roa_without_route_object"),
            ]
        );
    }
}
