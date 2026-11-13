//! RTR PDU codec for protocol versions 0 (RFC 6810), 1 (RFC 8210) and 2
//! (draft-ietf-sidrops-8210bis, adds ASPA).
//!
//! Decoding is strict: every fixed-size PDU must have exactly its specified
//! length, variable PDUs are bounds-checked, and nothing indexes past the
//! input. Router Key (type 9) PDUs are recognised and skipped; ASPA (type
//! 11) PDUs are decoded on version 2 and skipped on older versions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::prefix::Prefix;
use crate::vrp::Vrp;

pub const HEADER_LEN: usize = 8;
/// Largest PDU accepted. Real PDUs are tiny; this bounds Error Report and
/// Router Key payloads so a hostile cache cannot make us allocate much.
pub const MAX_PDU_LEN: u32 = 64 * 1024;

pub const TYPE_SERIAL_NOTIFY: u8 = 0;
pub const TYPE_SERIAL_QUERY: u8 = 1;
pub const TYPE_RESET_QUERY: u8 = 2;
pub const TYPE_CACHE_RESPONSE: u8 = 3;
pub const TYPE_IPV4_PREFIX: u8 = 4;
pub const TYPE_IPV6_PREFIX: u8 = 6;
pub const TYPE_END_OF_DATA: u8 = 7;
pub const TYPE_CACHE_RESET: u8 = 8;
pub const TYPE_ROUTER_KEY: u8 = 9;
pub const TYPE_ERROR_REPORT: u8 = 10;
pub const TYPE_ASPA: u8 = 11;

/// Error Report codes (RFC 8210 section 12).
pub const ERR_CORRUPT_DATA: u16 = 0;
pub const ERR_NO_DATA: u16 = 2;
pub const ERR_UNSUPPORTED_VERSION: u16 = 4;
pub const ERR_UNSUPPORTED_PDU: u16 = 5;
/// 8210bis: ASPA provider list error.
pub const ERR_ASPA_PROVIDER_LIST: u16 = 9;
/// Highest protocol version this codec speaks.
pub const MAX_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
}

impl Timing {
    /// RFC 8210 section 6 defaults, also used for version 0 sessions.
    pub const DEFAULT: Timing = Timing {
        refresh: 3600,
        retry: 600,
        expire: 7200,
    };

    /// Clamps values into the ranges allowed by RFC 8210 section 6.
    pub fn clamped(self) -> Timing {
        Timing {
            refresh: self.refresh.clamp(1, 86_400),
            retry: self.retry.clamp(1, 7_200),
            expire: self.expire.clamp(600, 172_800),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pdu {
    SerialNotify {
        version: u8,
        session_id: u16,
        serial: u32,
    },
    SerialQuery {
        version: u8,
        session_id: u16,
        serial: u32,
    },
    ResetQuery {
        version: u8,
    },
    CacheResponse {
        version: u8,
        session_id: u16,
    },
    Prefix {
        version: u8,
        announce: bool,
        vrp: Vrp,
    },
    EndOfData {
        version: u8,
        session_id: u16,
        serial: u32,
        /// Present for version 1 only.
        timing: Option<Timing>,
    },
    CacheReset {
        version: u8,
    },
    ErrorReport {
        version: u8,
        code: u16,
        pdu: Vec<u8>,
        text: String,
    },
    /// ASPA record (version 2). A withdrawal carries no providers.
    Aspa {
        version: u8,
        announce: bool,
        customer: u32,
        providers: Vec<u32>,
    },
    /// Router Key PDU, or ASPA on version < 2: well-formed but not used.
    Ignored {
        version: u8,
        pdu_type: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PduError {
    #[error("PDU truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("PDU length {0} is out of bounds")]
    BadLength(u32),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported PDU type {0}")]
    UnsupportedType(u8),
    #[error("malformed PDU: {0}")]
    Malformed(&'static str),
    #[error("ASPA provider list error: {0}")]
    AspaProviders(&'static str),
}

impl PduError {
    /// RTR error code to report back to the cache.
    pub fn code(&self) -> u16 {
        match self {
            PduError::UnsupportedVersion(_) => ERR_UNSUPPORTED_VERSION,
            PduError::UnsupportedType(_) => ERR_UNSUPPORTED_PDU,
            PduError::AspaProviders(_) => ERR_ASPA_PROVIDER_LIST,
            _ => ERR_CORRUPT_DATA,
        }
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Validates a PDU header and returns the total PDU length it announces.
pub fn header_length(header: &[u8; HEADER_LEN]) -> Result<usize, PduError> {
    if header[0] > MAX_VERSION {
        return Err(PduError::UnsupportedVersion(header[0]));
    }
    let len = u32_at(header, 4);
    if (len as usize) < HEADER_LEN || len > MAX_PDU_LEN {
        return Err(PduError::BadLength(len));
    }
    Ok(len as usize)
}

/// Decodes exactly one PDU. `buf` must contain the whole PDU and nothing else.
pub fn decode(buf: &[u8]) -> Result<Pdu, PduError> {
    if buf.len() < HEADER_LEN {
        return Err(PduError::Truncated {
            need: HEADER_LEN,
            have: buf.len(),
        });
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&buf[..HEADER_LEN]);
    let len = header_length(&header)?;
    if buf.len() < len {
        return Err(PduError::Truncated {
            need: len,
            have: buf.len(),
        });
    }
    if buf.len() > len {
        return Err(PduError::Malformed("trailing bytes after PDU"));
    }
    let version = buf[0];
    let pdu_type = buf[1];
    let field = u16_at(buf, 2);

    let expect = |n: usize| {
        if len == n {
            Ok(())
        } else {
            Err(PduError::BadLength(len as u32))
        }
    };

    match pdu_type {
        TYPE_SERIAL_NOTIFY | TYPE_SERIAL_QUERY => {
            expect(12)?;
            let serial = u32_at(buf, 8);
            Ok(if pdu_type == TYPE_SERIAL_NOTIFY {
                Pdu::SerialNotify {
                    version,
                    session_id: field,
                    serial,
                }
            } else {
                Pdu::SerialQuery {
                    version,
                    session_id: field,
                    serial,
                }
            })
        }
        TYPE_RESET_QUERY => {
            expect(8)?;
            Ok(Pdu::ResetQuery { version })
        }
        TYPE_CACHE_RESPONSE => {
            expect(8)?;
            Ok(Pdu::CacheResponse {
                version,
                session_id: field,
            })
        }
        TYPE_CACHE_RESET => {
            expect(8)?;
            Ok(Pdu::CacheReset { version })
        }
        TYPE_IPV4_PREFIX | TYPE_IPV6_PREFIX => {
            let v6 = pdu_type == TYPE_IPV6_PREFIX;
            expect(if v6 { 32 } else { 20 })?;
            let flags = buf[8];
            let prefix_len = buf[9];
            let max_len = buf[10];
            let (addr, asn_at) = if v6 {
                let mut a = [0u8; 16];
                a.copy_from_slice(&buf[12..28]);
                (IpAddr::V6(Ipv6Addr::from(a)), 28)
            } else {
                (
                    IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])),
                    16,
                )
            };
            let prefix =
                Prefix::new(addr, prefix_len).map_err(|_| PduError::Malformed("bad prefix"))?;
            let vrp = Vrp::new(prefix, max_len, u32_at(buf, asn_at))
                .map_err(|_| PduError::Malformed("bad max length"))?;
            Ok(Pdu::Prefix {
                version,
                announce: flags & 1 == 1,
                vrp,
            })
        }
        TYPE_END_OF_DATA => {
            let serial_and_timing = if version == 0 {
                expect(12)?;
                (u32_at(buf, 8), None)
            } else {
                expect(24)?;
                (
                    u32_at(buf, 8),
                    Some(Timing {
                        refresh: u32_at(buf, 12),
                        retry: u32_at(buf, 16),
                        expire: u32_at(buf, 20),
                    }),
                )
            };
            Ok(Pdu::EndOfData {
                version,
                session_id: field,
                serial: serial_and_timing.0,
                timing: serial_and_timing.1,
            })
        }
        TYPE_ERROR_REPORT => {
            let pdu_len_end = 12;
            if len < pdu_len_end {
                return Err(PduError::BadLength(len as u32));
            }
            let pdu_len = u32_at(buf, 8) as usize;
            let text_len_at = pdu_len_end
                .checked_add(pdu_len)
                .filter(|&n| n.checked_add(4).is_some_and(|m| m <= len))
                .ok_or(PduError::Malformed("error report PDU length"))?;
            let text_len = u32_at(buf, text_len_at) as usize;
            let text_at = text_len_at + 4;
            if text_at.checked_add(text_len) != Some(len) {
                return Err(PduError::Malformed("error report text length"));
            }
            Ok(Pdu::ErrorReport {
                version,
                code: field,
                pdu: buf[pdu_len_end..text_len_at].to_vec(),
                text: String::from_utf8_lossy(&buf[text_at..]).into_owned(),
            })
        }
        TYPE_ASPA if version >= 2 => {
            if len < 12 || (len - 12) % 4 != 0 {
                return Err(PduError::BadLength(len as u32));
            }
            let announce = buf[2] & 1 == 1;
            let customer = u32_at(buf, 8);
            let providers: Vec<u32> = buf[12..].chunks_exact(4).map(|c| u32_at(c, 0)).collect();
            if announce {
                if providers.is_empty() {
                    return Err(PduError::AspaProviders("announcement without providers"));
                }
                if !providers.windows(2).all(|w| w[0] < w[1]) {
                    return Err(PduError::AspaProviders("providers not strictly increasing"));
                }
                if providers.len() > 1 && providers.contains(&0) {
                    return Err(PduError::AspaProviders("AS0 listed with other providers"));
                }
            } else if !providers.is_empty() {
                return Err(PduError::AspaProviders("withdrawal with providers"));
            }
            Ok(Pdu::Aspa {
                version,
                announce,
                customer,
                providers,
            })
        }
        TYPE_ROUTER_KEY | TYPE_ASPA => Ok(Pdu::Ignored { version, pdu_type }),
        other => Err(PduError::UnsupportedType(other)),
    }
}

fn header(out: &mut Vec<u8>, version: u8, pdu_type: u8, field: u16, len: u32) {
    out.push(version);
    out.push(pdu_type);
    out.extend_from_slice(&field.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
}

impl Pdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        match self {
            Pdu::SerialNotify {
                version,
                session_id,
                serial,
            }
            | Pdu::SerialQuery {
                version,
                session_id,
                serial,
            } => {
                let t = if matches!(self, Pdu::SerialNotify { .. }) {
                    TYPE_SERIAL_NOTIFY
                } else {
                    TYPE_SERIAL_QUERY
                };
                header(&mut out, *version, t, *session_id, 12);
                out.extend_from_slice(&serial.to_be_bytes());
            }
            Pdu::ResetQuery { version } => header(&mut out, *version, TYPE_RESET_QUERY, 0, 8),
            Pdu::CacheResponse {
                version,
                session_id,
            } => header(&mut out, *version, TYPE_CACHE_RESPONSE, *session_id, 8),
            Pdu::CacheReset { version } => header(&mut out, *version, TYPE_CACHE_RESET, 0, 8),
            Pdu::Prefix {
                version,
                announce,
                vrp,
            } => {
                let (t, len) = match vrp.prefix.addr() {
                    IpAddr::V4(_) => (TYPE_IPV4_PREFIX, 20),
                    IpAddr::V6(_) => (TYPE_IPV6_PREFIX, 32),
                };
                header(&mut out, *version, t, 0, len);
                out.extend_from_slice(&[u8::from(*announce), vrp.prefix.len(), vrp.max_length, 0]);
                match vrp.prefix.addr() {
                    IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
                    IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
                }
                out.extend_from_slice(&vrp.asn.to_be_bytes());
            }
            Pdu::EndOfData {
                version,
                session_id,
                serial,
                timing,
            } => {
                let len = if timing.is_some() { 24 } else { 12 };
                header(&mut out, *version, TYPE_END_OF_DATA, *session_id, len);
                out.extend_from_slice(&serial.to_be_bytes());
                if let Some(t) = timing {
                    out.extend_from_slice(&t.refresh.to_be_bytes());
                    out.extend_from_slice(&t.retry.to_be_bytes());
                    out.extend_from_slice(&t.expire.to_be_bytes());
                }
            }
            Pdu::ErrorReport {
                version,
                code,
                pdu,
                text,
            } => {
                // Clip so the encoded PDU always fits MAX_PDU_LEN.
                let pdu = &pdu[..pdu.len().min(1024)];
                let text = &text.as_bytes()[..text.len().min(1024)];
                let len = 16 + pdu.len() + text.len();
                header(&mut out, *version, TYPE_ERROR_REPORT, *code, len as u32);
                out.extend_from_slice(&(pdu.len() as u32).to_be_bytes());
                out.extend_from_slice(pdu);
                out.extend_from_slice(&(text.len() as u32).to_be_bytes());
                out.extend_from_slice(text);
            }
            Pdu::Aspa {
                version,
                announce,
                customer,
                providers,
            } => {
                let providers = &providers[..providers.len().min(crate::vrp::MAX_ASPA_PROVIDERS)];
                let len = 12 + 4 * providers.len();
                out.push(*version);
                out.push(TYPE_ASPA);
                out.push(u8::from(*announce));
                out.push(0);
                out.extend_from_slice(&(len as u32).to_be_bytes());
                out.extend_from_slice(&customer.to_be_bytes());
                for p in providers {
                    out.extend_from_slice(&p.to_be_bytes());
                }
            }
            Pdu::Ignored { version, pdu_type } => header(&mut out, *version, *pdu_type, 0, 8),
        }
        out
    }

    pub fn version(&self) -> u8 {
        match self {
            Pdu::SerialNotify { version, .. }
            | Pdu::SerialQuery { version, .. }
            | Pdu::ResetQuery { version }
            | Pdu::CacheResponse { version, .. }
            | Pdu::Prefix { version, .. }
            | Pdu::EndOfData { version, .. }
            | Pdu::CacheReset { version }
            | Pdu::ErrorReport { version, .. }
            | Pdu::Aspa { version, .. }
            | Pdu::Ignored { version, .. } => *version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp(p: &str, max: u8, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), max, asn).unwrap()
    }

    #[test]
    fn roundtrip_all_types() {
        let pdus = [
            Pdu::SerialNotify {
                version: 1,
                session_id: 7,
                serial: 42,
            },
            Pdu::SerialQuery {
                version: 1,
                session_id: 7,
                serial: 42,
            },
            Pdu::ResetQuery { version: 0 },
            Pdu::CacheResponse {
                version: 1,
                session_id: 7,
            },
            Pdu::Prefix {
                version: 1,
                announce: true,
                vrp: vrp("192.0.2.0/24", 24, 64500),
            },
            Pdu::Prefix {
                version: 1,
                announce: false,
                vrp: vrp("2001:db8::/32", 48, 64501),
            },
            Pdu::EndOfData {
                version: 1,
                session_id: 7,
                serial: 43,
                timing: Some(Timing::DEFAULT),
            },
            Pdu::EndOfData {
                version: 0,
                session_id: 7,
                serial: 43,
                timing: None,
            },
            Pdu::CacheReset { version: 1 },
            Pdu::ErrorReport {
                version: 1,
                code: 2,
                pdu: vec![1, 2, 3],
                text: "no data".into(),
            },
        ];
        for p in pdus {
            assert_eq!(decode(&p.encode()), Ok(p.clone()), "{p:?}");
        }
    }

    #[test]
    fn decodes_known_ipv4_bytes() {
        let bytes = [
            1, 4, 0, 0, 0, 0, 0, 20, // header
            1, 24, 24, 0, // flags, len, max, zero
            198, 51, 100, 0, // prefix
            0, 0, 0xfb, 0xf4, // AS64500
        ];
        assert_eq!(
            decode(&bytes),
            Ok(Pdu::Prefix {
                version: 1,
                announce: true,
                vrp: vrp("198.51.100.0/24", 24, 64500),
            })
        );
    }

    #[test]
    fn truncated() {
        let full = Pdu::Prefix {
            version: 1,
            announce: true,
            vrp: vrp("192.0.2.0/24", 24, 64500),
        }
        .encode();
        assert_eq!(
            decode(&full[..19]),
            Err(PduError::Truncated { need: 20, have: 19 })
        );
        assert_eq!(
            decode(&full[..3]),
            Err(PduError::Truncated { need: 8, have: 3 })
        );
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn wrong_fixed_length_rejected() {
        // Reset Query claiming 12 bytes.
        let mut b = Pdu::ResetQuery { version: 1 }.encode();
        b[7] = 12;
        b.extend_from_slice(&[0; 4]);
        assert_eq!(decode(&b), Err(PduError::BadLength(12)));
        // v1 End of Data with v0 length.
        let mut b = Pdu::EndOfData {
            version: 0,
            session_id: 1,
            serial: 1,
            timing: None,
        }
        .encode();
        b[0] = 1;
        assert_eq!(decode(&b), Err(PduError::BadLength(12)));
    }

    #[test]
    fn oversized_and_undersized_length() {
        let mut h = [1u8, 10, 0, 0, 0, 0, 0, 0];
        h[4..8].copy_from_slice(&(MAX_PDU_LEN + 1).to_be_bytes());
        assert_eq!(header_length(&h), Err(PduError::BadLength(MAX_PDU_LEN + 1)));
        h[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(header_length(&h), Err(PduError::BadLength(u32::MAX)));
        h[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(header_length(&h), Err(PduError::BadLength(4)));
        h[4..8].copy_from_slice(&MAX_PDU_LEN.to_be_bytes());
        assert_eq!(header_length(&h), Ok(MAX_PDU_LEN as usize));
    }

    #[test]
    fn unknown_type_and_version() {
        let b = [1u8, 5, 0, 0, 0, 0, 0, 8];
        assert_eq!(decode(&b), Err(PduError::UnsupportedType(5)));
        assert_eq!(PduError::UnsupportedType(5).code(), ERR_UNSUPPORTED_PDU);
        let b = [1u8, 200, 0, 0, 0, 0, 0, 8];
        assert_eq!(decode(&b), Err(PduError::UnsupportedType(200)));
        let b = [3u8, 2, 0, 0, 0, 0, 0, 8];
        assert_eq!(decode(&b), Err(PduError::UnsupportedVersion(3)));
        // Version 2 is accepted.
        assert_eq!(
            decode(&[2u8, 2, 0, 0, 0, 0, 0, 8]),
            Ok(Pdu::ResetQuery { version: 2 })
        );
    }

    #[test]
    fn router_key_and_aspa_are_ignored() {
        let mut rk = vec![1u8, 9, 0, 0, 0, 0, 0, 40];
        rk.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            decode(&rk),
            Ok(Pdu::Ignored {
                version: 1,
                pdu_type: 9
            })
        );
        let mut aspa = vec![1u8, 11, 0, 0, 0, 0, 0, 16];
        aspa.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            decode(&aspa),
            Ok(Pdu::Ignored {
                version: 1,
                pdu_type: 11
            })
        );
    }

    #[test]
    fn aspa_v2() {
        let a = Pdu::Aspa {
            version: 2,
            announce: true,
            customer: 64500,
            providers: vec![64510, 64511],
        };
        let bytes = a.encode();
        assert_eq!(
            bytes,
            [2, 11, 1, 0, 0, 0, 0, 20, 0, 0, 0xfb, 0xf4, 0, 0, 0xfb, 0xfe, 0, 0, 0xfb, 0xff]
        );
        assert_eq!(decode(&bytes), Ok(a));
        let w = Pdu::Aspa {
            version: 2,
            announce: false,
            customer: 64500,
            providers: vec![],
        };
        assert_eq!(decode(&w.encode()), Ok(w.clone()));
        // Unsorted providers, duplicates, AS0 mixed, empty announce, withdraw with list.
        for providers in [vec![2u32, 1], vec![1, 1], vec![0, 5], vec![]] {
            let mut b = Pdu::Aspa {
                version: 2,
                announce: true,
                customer: 1,
                providers,
            }
            .encode();
            assert!(
                matches!(decode(&b), Err(PduError::AspaProviders(_))),
                "{b:?}"
            );
            b[2] = 0;
            if b.len() > 12 {
                assert!(decode(&b).is_err());
            }
        }
        assert_eq!(PduError::AspaProviders("x").code(), ERR_ASPA_PROVIDER_LIST);
        // Ragged length.
        let mut b = w.encode();
        b.extend_from_slice(&[0, 0]);
        b[7] = 14;
        assert_eq!(decode(&b), Err(PduError::BadLength(14)));
    }

    #[test]
    fn invalid_prefix_contents() {
        // prefix length 33
        let b = [
            1u8, 4, 0, 0, 0, 0, 0, 20, 1, 33, 33, 0, 192, 0, 2, 0, 0, 0, 0, 1,
        ];
        assert_eq!(decode(&b), Err(PduError::Malformed("bad prefix")));
        // max length below prefix length
        let b = [
            1u8, 4, 0, 0, 0, 0, 0, 20, 1, 24, 16, 0, 192, 0, 2, 0, 0, 0, 0, 1,
        ];
        assert_eq!(decode(&b), Err(PduError::Malformed("bad max length")));
        // host bits set
        let b = [
            1u8, 4, 0, 0, 0, 0, 0, 20, 1, 24, 24, 0, 192, 0, 2, 9, 0, 0, 0, 1,
        ];
        assert_eq!(decode(&b), Err(PduError::Malformed("bad prefix")));
    }

    #[test]
    fn error_report_bounds() {
        // Encapsulated PDU length points past the end.
        let mut b = vec![1u8, 10, 0, 2, 0, 0, 0, 16];
        b.extend_from_slice(&1000u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(decode(&b), Err(PduError::Malformed(_))));
        // Huge lengths must not overflow.
        let mut b = vec![1u8, 10, 0, 2, 0, 0, 0, 16];
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&b).is_err());
        // Text length mismatch.
        let mut b = vec![1u8, 10, 0, 2, 0, 0, 0, 18];
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&5u32.to_be_bytes());
        b.extend_from_slice(b"hi");
        assert!(decode(&b).is_err());
        // Too short to hold the length fields.
        let b = [1u8, 10, 0, 2, 0, 0, 0, 8];
        assert_eq!(decode(&b), Err(PduError::BadLength(8)));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut b = Pdu::ResetQuery { version: 1 }.encode();
        b.push(0);
        assert!(decode(&b).is_err());
    }

    #[test]
    fn decode_never_panics_on_garbage() {
        // Deterministic pseudo-random fuzz over every type byte and many lengths.
        let mut seed: u32 = 0x1234_5678;
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let len = (seed % 48) as usize;
            let mut b: Vec<u8> = (0..len)
                .map(|i| (seed.rotate_left(i as u32) & 0xff) as u8)
                .collect();
            if b.len() >= 8 {
                b[0] %= 3;
                b[1] %= 12;
                b[4..8].copy_from_slice(&(len as u32).to_be_bytes());
            }
            let _ = decode(&b);
        }
    }

    #[test]
    fn timing_clamp() {
        let t = Timing {
            refresh: 0,
            retry: 100_000,
            expire: 1,
        }
        .clamped();
        assert_eq!(
            t,
            Timing {
                refresh: 1,
                retry: 7200,
                expire: 600
            }
        );
    }
}
