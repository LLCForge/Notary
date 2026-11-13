//! `notary bench`: measures table build, route validation, JSON parsing and
//! RTR PDU decoding on this machine. Synthetic data is deterministic.

use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use serde::Serialize;

use crate::prefix::Prefix;
use crate::rtr::pdu::{decode, Pdu};
use crate::validator::validate;
use crate::vrp::{parse_json, Vrp, VrpData, VrpTable};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// Synthetic VRP set shaped like the global one: mostly /24 (v4) and /48
/// (v6) with some shorter prefixes and maxLength ranges.
pub fn synthetic(v4: usize, v6: usize, seed: u64) -> Vec<Vrp> {
    let mut r = Rng(seed.max(1));
    let mut out = Vec::with_capacity(v4 + v6);
    for _ in 0..v4 {
        let x = r.next();
        let len = [24u8, 24, 24, 24, 23, 22, 20, 16][(x % 8) as usize];
        let addr = Ipv4Addr::from(((x >> 8) as u32) & (u32::MAX << (32 - len)));
        let max = if x.is_multiple_of(5) {
            24.max(len)
        } else {
            len
        };
        if let Ok(p) = Prefix::new(addr.into(), len) {
            if let Ok(v) = Vrp::new(p, max, 64_496 + ((x >> 40) % 100_000) as u32) {
                out.push(v);
            }
        }
    }
    for _ in 0..v6 {
        let x = r.next();
        let len = [48u8, 48, 48, 32, 36, 40, 44, 29][(x % 8) as usize];
        // Spread over 2000::/3 like global unicast; a shared prefix would make
        // every short VRP cover every query, which no real table does.
        let bits =
            ((1u128 << 125) | (u128::from(r.next()) << 61)) & (u128::MAX << (128 - u32::from(len)));
        let max = if x.is_multiple_of(4) {
            48.max(len)
        } else {
            len
        };
        if let Ok(p) = Prefix::new(Ipv6Addr::from(bits).into(), len) {
            if let Ok(v) = Vrp::new(p, max, 64_496 + ((x >> 40) % 100_000) as u32) {
                out.push(v);
            }
        }
    }
    out
}

#[derive(Debug, Serialize)]
pub struct BenchReport {
    pub vrps: usize,
    pub source: String,
    pub build_ms: f64,
    pub lookups: usize,
    pub lookups_per_sec: f64,
    pub ns_per_lookup: f64,
    pub json_mib: f64,
    pub json_parse_ms: f64,
    pub json_mib_per_sec: f64,
    pub pdu_count: usize,
    pub pdu_decode_per_sec: f64,
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

pub fn run(data: Option<VrpData>, v4: usize, v6: usize, lookups: usize) -> BenchReport {
    let (vrps, source) = match data {
        Some(d) => {
            let n = d.vrps.len();
            (d.vrps, format!("{n} VRPs from the given source"))
        }
        None => (
            synthetic(v4, v6, 0x5eed),
            format!("synthetic {v4} IPv4 + {v6} IPv6"),
        ),
    };

    let t = Instant::now();
    let table = VrpTable::from_vrps(vrps.iter().copied());
    let build_ms = ms(t);

    // Half the queries hit a VRP prefix (more specific by one bit when
    // possible), half are random space.
    let mut r = Rng(0xbeef);
    let routes: Vec<(Prefix, u32)> = (0..lookups)
        .filter_map(|i| {
            let x = r.next();
            if i % 2 == 0 && !vrps.is_empty() {
                let v = vrps[(x as usize) % vrps.len()];
                Some((
                    v.prefix,
                    if x.is_multiple_of(3) {
                        v.asn
                    } else {
                        v.asn.wrapping_add(1)
                    },
                ))
            } else {
                let a = Ipv4Addr::from(((x >> 16) as u32) & 0xffff_ff00);
                Prefix::new(a.into(), 24).ok().map(|p| (p, 64_500))
            }
        })
        .collect();
    let lookups = routes.len();
    let t = Instant::now();
    for (p, a) in &routes {
        black_box(validate(&table, p, *a).validity);
    }
    let secs = t.elapsed().as_secs_f64().max(1e-9);

    #[derive(Serialize)]
    struct Roa {
        prefix: String,
        #[serde(rename = "maxLength")]
        max_length: u8,
        asn: String,
        ta: &'static str,
    }
    let json = serde_json::to_vec(&serde_json::json!({
        "roas": vrps.iter().map(|v| Roa {
            prefix: v.prefix.to_string(),
            max_length: v.max_length,
            asn: format!("AS{}", v.asn),
            ta: "test",
        }).collect::<Vec<_>>()
    }))
    .unwrap_or_default();
    let t = Instant::now();
    let parsed = parse_json(&json).map(|v| v.len()).unwrap_or(0);
    black_box(parsed);
    let json_parse_ms = ms(t);
    let json_mib = json.len() as f64 / (1024.0 * 1024.0);

    let pdus: Vec<Vec<u8>> = vrps
        .iter()
        .map(|&vrp| {
            Pdu::Prefix {
                version: 1,
                announce: true,
                vrp,
            }
            .encode()
        })
        .collect();
    let t = Instant::now();
    for b in &pdus {
        let _ = black_box(decode(b));
    }
    let pdu_secs = t.elapsed().as_secs_f64().max(1e-9);

    BenchReport {
        vrps: table.len(),
        source,
        build_ms,
        lookups,
        lookups_per_sec: lookups as f64 / secs,
        ns_per_lookup: secs * 1e9 / lookups.max(1) as f64,
        json_mib,
        json_parse_ms,
        json_mib_per_sec: json_mib / (json_parse_ms / 1000.0).max(1e-9),
        pdu_count: pdus.len(),
        pdu_decode_per_sec: pdus.len() as f64 / pdu_secs,
    }
}

pub fn print(r: &BenchReport) {
    println!("Data      {} ({} unique VRPs)", r.source, r.vrps);
    println!("Build     {:>10.1} ms  trie index", r.build_ms);
    println!(
        "Validate  {:>10.0} routes/s  ({:.0} ns per route, {} routes)",
        r.lookups_per_sec, r.ns_per_lookup, r.lookups
    );
    println!(
        "JSON      {:>10.1} MiB/s  ({:.1} MiB in {:.0} ms)",
        r.json_mib_per_sec, r.json_mib, r.json_parse_ms
    );
    println!(
        "RTR PDUs  {:>10.0} PDUs/s decoded ({} PDUs)",
        r.pdu_decode_per_sec, r.pdu_count
    );
    if cfg!(debug_assertions) {
        println!("note: debug build; use `cargo run --release -- bench` for real numbers");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_is_deterministic_and_valid() {
        let a = synthetic(1000, 200, 7);
        assert_eq!(a, synthetic(1000, 200, 7));
        assert!(a.len() > 1100);
        let r = run(Some(VrpData::from_vrps(a)), 0, 0, 2000);
        assert!(r.vrps > 1000);
        assert_eq!(r.lookups, 2000);
        assert!(r.lookups_per_sec > 0.0);
        assert_eq!(r.pdu_count, r.vrps);
    }
}
