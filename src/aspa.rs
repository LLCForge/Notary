//! ASPA-based AS_PATH verification (draft-ietf-sidrops-aspa-verification,
//! sections 5.3 - 5.6). Pure functions, no I/O.

use std::fmt;

use serde::Serialize;

use crate::vrp::VrpTable;

/// Longest AS_PATH accepted for verification (after prepend removal).
pub const MAX_PATH_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Hop {
    NoAttestation,
    ProviderPlus,
    NotProviderPlus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Route received from a customer, lateral peer or route server.
    Upstream,
    /// Route received from a provider.
    Downstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AspaState {
    Valid,
    Invalid,
    Unknown,
}

impl fmt::Display for AspaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AspaState::Valid => "VALID",
            AspaState::Invalid => "INVALID",
            AspaState::Unknown => "UNKNOWN",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AspaResult {
    pub state: AspaState,
    pub direction: Direction,
    /// Path as given (neighbor first, origin last), prepends removed.
    pub path: Vec<u32>,
    /// One entry per adjacent pair, origin side first:
    /// `(customer, candidate provider, outcome)`.
    pub hops: Vec<(u32, u32, Hop)>,
}

/// `authorized(AS x, AS y)`: is `y` an attested provider of `x`?
pub fn hop(table: &VrpTable, customer: u32, provider: u32) -> Hop {
    match table.aspa(customer) {
        None => Hop::NoAttestation,
        Some(p) if p.binary_search(&provider).is_ok() => Hop::ProviderPlus,
        Some(_) => Hop::NotProviderPlus,
    }
}

/// Parses an AS_PATH written as in `show ip bgp` (neighbor first, origin
/// last), separated by spaces or commas, with optional `AS` prefixes.
/// AS_SETs (`{...}`) are rejected.
pub fn parse_path(s: &str) -> anyhow::Result<Vec<u32>> {
    if s.contains(['{', '}', '[', ']']) {
        anyhow::bail!("AS_PATH contains an AS_SET; such routes are Invalid (RFC 9774)");
    }
    let path = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .map(|t| crate::prefix::parse_asn(t).map_err(|e| anyhow::anyhow!("{t:?}: {e}")))
        .collect::<anyhow::Result<Vec<u32>>>()?;
    if path.len() > MAX_PATH_LEN * 4 {
        anyhow::bail!("AS_PATH too long");
    }
    Ok(path)
}

/// Verifies `path` (neighbor first, origin last).
pub fn verify(table: &VrpTable, path: &[u32], direction: Direction) -> AspaResult {
    let mut p: Vec<u32> = path.to_vec();
    p.dedup();
    // The draft numbers the path from the origin: A(1) = origin, A(N) = neighbor.
    p.reverse();
    let n = p.len();
    let hops: Vec<(u32, u32, Hop)> = p
        .windows(2)
        .map(|w| (w[0], w[1], hop(table, w[0], w[1])))
        .collect();
    // Reverse direction hops: authorized(A(j), A(j-1)) for j = N..2.
    let down = |j: usize| hop(table, p[j - 1], p[j - 2]);

    let state = if n == 0 || n > MAX_PATH_LEN {
        AspaState::Invalid
    } else {
        // Up-ramp: lowest 1-based index I with authorized(A(I), A(I+1)) failing.
        let ramp_up =
            |bad: &dyn Fn(Hop) -> bool| hops.iter().position(|h| bad(h.2)).map_or(n, |i| i + 1);
        let max_up = ramp_up(&|h| h == Hop::NotProviderPlus);
        let min_up = ramp_up(&|h| h != Hop::ProviderPlus);
        let (max_down, min_down) = match direction {
            Direction::Upstream => (0, 0),
            Direction::Downstream => {
                let ramp_down = |bad: &dyn Fn(Hop) -> bool| {
                    (2..=n)
                        .rev()
                        .find(|&j| bad(down(j)))
                        .map_or(n, |j| n - j + 1)
                };
                (
                    ramp_down(&|h| h == Hop::NotProviderPlus),
                    ramp_down(&|h| h != Hop::ProviderPlus),
                )
            }
        };
        if max_up + max_down < n {
            AspaState::Invalid
        } else if min_up + min_down < n {
            AspaState::Unknown
        } else {
            AspaState::Valid
        }
    };
    p.reverse();
    AspaResult {
        state,
        direction,
        path: p,
        hops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrp::VrpData;

    /// Customer -> providers.
    fn table(aspas: &[(u32, &[u32])]) -> VrpTable {
        let mut d = VrpData::default();
        for (c, p) in aspas {
            d.aspas.insert(*c, p.to_vec());
        }
        VrpTable::build(d)
    }

    fn up(t: &VrpTable, path: &[u32]) -> AspaState {
        verify(t, path, Direction::Upstream).state
    }

    fn down(t: &VrpTable, path: &[u32]) -> AspaState {
        verify(t, path, Direction::Downstream).state
    }

    #[test]
    fn hop_outcomes() {
        let t = table(&[(64500, &[64510])]);
        assert_eq!(hop(&t, 64500, 64510), Hop::ProviderPlus);
        assert_eq!(hop(&t, 64500, 64511), Hop::NotProviderPlus);
        assert_eq!(hop(&t, 64501, 64510), Hop::NoAttestation);
    }

    #[test]
    fn upstream() {
        // Origin 64500 -> provider 64510 -> provider 64520 (neighbor).
        let t = table(&[(64500, &[64510]), (64510, &[64520])]);
        assert_eq!(up(&t, &[64520, 64510, 64500]), AspaState::Valid);
        assert_eq!(up(&t, &[64500]), AspaState::Valid);
        // Prepends are ignored.
        assert_eq!(
            up(&t, &[64520, 64510, 64510, 64500, 64500]),
            AspaState::Valid
        );
        // 64510 sending to a non-provider 64530: leak.
        assert_eq!(up(&t, &[64530, 64510, 64500]), AspaState::Invalid);
        // Unattested hop.
        let t2 = table(&[(64500, &[64510])]);
        assert_eq!(up(&t2, &[64520, 64510, 64500]), AspaState::Unknown);
        assert_eq!(up(&t, &[]), AspaState::Invalid);
    }

    #[test]
    fn downstream() {
        // 64500 -> up to 64510 -> up to 64520 (top) -> down to 64530 -> down to 64540 (neighbor of us).
        let t = table(&[
            (64500, &[64510]),
            (64510, &[64520]),
            (64530, &[64520]),
            (64540, &[64530]),
        ]);
        assert_eq!(
            down(&t, &[64540, 64530, 64520, 64510, 64500]),
            AspaState::Valid
        );
        // Valley: down then up again (64530 is not a provider of 64520... and
        // 64520 not a provider of 64540).
        let t = table(&[
            (64500, &[64510]),
            (64510, &[64599]),
            (64520, &[64599]),
            (64530, &[64599]),
        ]);
        // path 64530 64520 64510 64500: 64500->64510 up ok, 64510->64520 not provider,
        // from the other side 64530->64520 not provider: valley.
        assert_eq!(down(&t, &[64530, 64520, 64510, 64500]), AspaState::Invalid);
        // Two-hop paths are always valid downstream.
        assert_eq!(down(&t, &[64599, 64500]), AspaState::Valid);
        // Unattested middle.
        let t = table(&[(64500, &[64510])]);
        assert_eq!(down(&t, &[64530, 64520, 64510, 64500]), AspaState::Unknown);
    }

    #[test]
    fn path_parsing() {
        assert_eq!(
            parse_path("AS64501 64500,64500").unwrap(),
            vec![64501, 64500, 64500]
        );
        assert!(parse_path("64501 {64502 64503}").is_err());
        assert!(parse_path("64501 x").is_err());
    }
}
