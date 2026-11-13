//! IP prefixes and AS numbers.
//!
//! Prefixes are stored left-aligned in a `u128` so IPv4 and IPv6 share the
//! same bit-walking code in the trie.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
    #[error("prefix must be written as address/length")]
    MissingLength,
    #[error("invalid IP address")]
    BadAddress,
    #[error("invalid prefix length")]
    BadLength,
    #[error("prefix length {len} exceeds {max} for this address family")]
    LengthTooLong { len: u8, max: u8 },
    #[error("address has bits set beyond the prefix length (did you mean {0}?)")]
    HostBitsSet(String),
    #[error("invalid AS number")]
    BadAsn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const fn max_len(self) -> u8 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    family: Family,
    bits: u128,
    len: u8,
}

const fn mask(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len as u32)
    }
}

impl Prefix {
    /// Builds a prefix, rejecting lengths beyond the family maximum and
    /// addresses with host bits set.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let (family, bits) = match addr {
            IpAddr::V4(a) => (Family::V4, (u32::from(a) as u128) << 96),
            IpAddr::V6(a) => (Family::V6, u128::from(a)),
        };
        if len > family.max_len() {
            return Err(PrefixError::LengthTooLong {
                len,
                max: family.max_len(),
            });
        }
        let masked = bits & mask(len);
        if masked != bits {
            let canonical = Prefix {
                family,
                bits: masked,
                len,
            };
            return Err(PrefixError::HostBitsSet(canonical.to_string()));
        }
        Ok(Prefix { family, bits, len })
    }

    pub fn family(&self) -> Family {
        self.family
    }

    pub fn len(&self) -> u8 {
        self.len
    }

    /// Bit `i` (0 = most significant) of the network address.
    pub fn bit(&self, i: u8) -> bool {
        (self.bits >> (127 - i as u32)) & 1 == 1
    }

    pub fn addr(&self) -> IpAddr {
        match self.family {
            Family::V4 => IpAddr::V4(Ipv4Addr::from((self.bits >> 96) as u32)),
            Family::V6 => IpAddr::V6(Ipv6Addr::from(self.bits)),
        }
    }

    /// True when `other` is equal to or more specific than `self`.
    pub fn covers(&self, other: &Prefix) -> bool {
        self.family == other.family
            && self.len <= other.len
            && (other.bits & mask(self.len)) == self.bits
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.len)
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.trim().split_once('/').ok_or(PrefixError::MissingLength)?;
        let addr: IpAddr = addr.parse().map_err(|_| PrefixError::BadAddress)?;
        if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PrefixError::BadLength);
        }
        let len: u8 = len.parse().map_err(|_| PrefixError::BadLength)?;
        Prefix::new(addr, len)
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Parses `AS64500`, `as64500` or `64500`.
pub fn parse_asn(s: &str) -> Result<u32, PrefixError> {
    let s = s.trim();
    let digits = s
        .strip_prefix("AS")
        .or_else(|| s.strip_prefix("as"))
        .unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PrefixError::BadAsn);
    }
    digits.parse().map_err(|_| PrefixError::BadAsn)
}

/// An AS number that deserializes from either `64500` or `"AS64500"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Asn(pub u32);

impl<'de> Deserialize<'de> for Asn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u32),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(Asn(n)),
            Raw::Str(s) => parse_asn(&s).map(Asn).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays() {
        let p: Prefix = "192.0.2.0/24".parse().unwrap();
        assert_eq!(p.to_string(), "192.0.2.0/24");
        assert_eq!(p.family(), Family::V4);
        let p: Prefix = "2001:db8::/32".parse().unwrap();
        assert_eq!(p.to_string(), "2001:db8::/32");
        assert_eq!(p.len(), 32);
        let p: Prefix = "0.0.0.0/0".parse().unwrap();
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn rejects_bad_prefixes() {
        assert_eq!(
            "192.0.2.0".parse::<Prefix>(),
            Err(PrefixError::MissingLength)
        );
        assert_eq!(
            "192.0.2.0/33".parse::<Prefix>(),
            Err(PrefixError::LengthTooLong { len: 33, max: 32 })
        );
        assert_eq!(
            "192.0.2.1/24".parse::<Prefix>(),
            Err(PrefixError::HostBitsSet("192.0.2.0/24".into()))
        );
        assert_eq!(
            "192.0.2.0/+4".parse::<Prefix>(),
            Err(PrefixError::BadLength)
        );
        assert_eq!("nope/24".parse::<Prefix>(), Err(PrefixError::BadAddress));
        assert!("2001:db8::/129".parse::<Prefix>().is_err());
    }

    #[test]
    fn covers() {
        let a: Prefix = "198.51.100.0/22".parse().unwrap();
        let b: Prefix = "198.51.101.0/24".parse().unwrap();
        let c: Prefix = "203.0.113.0/24".parse().unwrap();
        let v6: Prefix = "2001:db8::/32".parse().unwrap();
        assert!(a.covers(&b));
        assert!(a.covers(&a));
        assert!(!b.covers(&a));
        assert!(!a.covers(&c));
        assert!(!v6.covers(&a));
        let all: Prefix = "0.0.0.0/0".parse().unwrap();
        assert!(all.covers(&c));
        assert!(!all.covers(&v6));
    }

    #[test]
    fn asn_parsing() {
        assert_eq!(parse_asn("AS64500"), Ok(64500));
        assert_eq!(parse_asn("as64501"), Ok(64501));
        assert_eq!(parse_asn("64502"), Ok(64502));
        assert_eq!(parse_asn("4294967295"), Ok(u32::MAX));
        assert!(parse_asn("4294967296").is_err());
        assert!(parse_asn("AS").is_err());
        assert!(parse_asn("-1").is_err());
        let a: Asn = serde_json::from_str("\"AS64496\"").unwrap();
        assert_eq!(a, Asn(64496));
        let a: Asn = serde_json::from_str("64497").unwrap();
        assert_eq!(a, Asn(64497));
    }
}
