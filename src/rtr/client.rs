//! RTR router-side client: Reset / Serial queries, incremental updates,
//! Serial Notify handling, ASPA (version 2) and version 2 -> 1 -> 0 fallback
//! over TCP, TLS or SSH.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::pdu::{self, Pdu, Timing, HEADER_LEN};
use super::transport::{self, RtrStream, RtrTarget};
use crate::state::{AppState, UpdateMeta};
use crate::vrp::{Vrp, VrpData};
/// Maximum silence while a response is in progress.
const PDU_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
#[error("cache does not support RTR version {0}")]
struct VersionUnsupported(u8);

/// A complete synchronised VRP set.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub vrps: HashSet<Vrp>,
    /// Customer AS -> providers (version 2 sessions only).
    pub aspas: BTreeMap<u32, Vec<u32>>,
    pub session_id: u16,
    pub serial: u32,
    pub timing: Timing,
    pub version: u8,
}

enum SyncResult {
    Done,
    CacheReset,
}

struct Conn {
    /// Read errors carry the RTR error code to report, if the cause was a bad PDU.
    rx: mpsc::Receiver<Result<Pdu, (Option<u16>, String)>>,
    writer: WriteHalf<Box<dyn RtrStream>>,
    version: u8,
    /// The reader owns the other half of the stream; aborting it on drop
    /// closes the connection (TLS / SSH streams do not close on a half drop).
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Snapshot {
    pub fn data(&self) -> VrpData {
        VrpData {
            vrps: self.vrps.iter().copied().collect(),
            aspas: self.aspas.clone(),
            expires: Default::default(),
        }
    }
}

async fn read_pdu<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Pdu> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let len = pdu::header_length(&header)?;
    let mut buf = vec![0u8; len];
    buf[..HEADER_LEN].copy_from_slice(&header);
    reader.read_exact(&mut buf[HEADER_LEN..]).await?;
    Ok(pdu::decode(&buf)?)
}

impl Conn {
    async fn open(target: &RtrTarget, version: u8) -> anyhow::Result<Conn> {
        let stream = transport::connect(target).await?;
        let (mut reader, writer) = tokio::io::split(stream);
        // A dedicated reader task keeps PDU framing intact regardless of how
        // the session logic waits on timers.
        let (tx, rx) = mpsc::channel(4096);
        let reader = tokio::spawn(async move {
            loop {
                let r = read_pdu(&mut reader).await.map_err(|e| {
                    let code = e.downcast_ref::<pdu::PduError>().map(pdu::PduError::code);
                    (code, format!("{e:#}"))
                });
                let stop = r.is_err();
                if tx.send(r).await.is_err() || stop {
                    break;
                }
            }
        });
        Ok(Conn {
            rx,
            writer,
            version,
            reader,
        })
    }

    async fn send(&mut self, pdu: &Pdu) -> anyhow::Result<()> {
        self.writer.write_all(&pdu.encode()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn recv(&mut self, wait: Option<Duration>) -> anyhow::Result<Option<Pdu>> {
        let next = match wait {
            Some(d) => match timeout(d, self.rx.recv()).await {
                Ok(n) => n,
                Err(_) => return Ok(None),
            },
            None => self.rx.recv().await,
        };
        match next {
            Some(Ok(p)) => Ok(Some(p)),
            Some(Err((code, e))) => {
                if let Some(code) = code {
                    // Best effort: tell the cache why we are dropping the session.
                    let report = Pdu::ErrorReport {
                        version: self.version,
                        code,
                        pdu: Vec::new(),
                        text: e.clone(),
                    };
                    let _ = self.writer.write_all(&report.encode()).await;
                    let _ = self.writer.flush().await;
                }
                Err(anyhow!("RTR read failed: {e}"))
            }
            None => bail!("RTR connection closed"),
        }
    }

    async fn expect_pdu(&mut self) -> anyhow::Result<Pdu> {
        self.recv(Some(PDU_TIMEOUT))
            .await?
            .ok_or_else(|| anyhow!("RTR cache stopped responding"))
    }

    /// Sends `query` and applies the response to `vrps` / `aspas`. On error
    /// they may be partially modified; callers work on a copy.
    async fn sync(
        &mut self,
        query: Pdu,
        vrps: &mut HashSet<Vrp>,
        aspas: &mut BTreeMap<u32, Vec<u32>>,
        session: &mut Option<u16>,
    ) -> anyhow::Result<(SyncResult, u32, Option<Timing>)> {
        self.send(&query).await?;
        let mut in_response = false;
        loop {
            let p = self.expect_pdu().await?;
            if let Pdu::ErrorReport { code, text, .. } = &p {
                if *code == pdu::ERR_UNSUPPORTED_VERSION {
                    return Err(VersionUnsupported(self.version).into());
                }
                if *code == pdu::ERR_NO_DATA {
                    bail!("cache has no data available yet");
                }
                bail!("cache sent error report {code}: {text}");
            }
            if p.version() != self.version {
                bail!(
                    "cache answered with RTR version {} on a version {} session",
                    p.version(),
                    self.version
                );
            }
            match p {
                Pdu::CacheResponse { session_id, .. } => {
                    if let Some(s) = *session {
                        if s != session_id {
                            bail!("session id changed from {s} to {session_id}");
                        }
                    }
                    *session = Some(session_id);
                    in_response = true;
                }
                Pdu::Prefix { announce, vrp, .. } => {
                    if !in_response {
                        bail!("prefix PDU outside of a cache response");
                    }
                    if announce {
                        vrps.insert(vrp);
                    } else {
                        vrps.remove(&vrp);
                    }
                }
                Pdu::Aspa {
                    announce,
                    customer,
                    providers,
                    ..
                } => {
                    if !in_response {
                        bail!("ASPA PDU outside of a cache response");
                    }
                    if announce {
                        aspas.insert(customer, providers);
                    } else {
                        aspas.remove(&customer);
                    }
                }
                Pdu::EndOfData {
                    session_id,
                    serial,
                    timing,
                    ..
                } => {
                    if !in_response || Some(session_id) != *session {
                        bail!("unexpected End of Data");
                    }
                    return Ok((SyncResult::Done, serial, timing));
                }
                Pdu::CacheReset { .. } => return Ok((SyncResult::CacheReset, 0, None)),
                Pdu::SerialNotify { .. } | Pdu::Ignored { .. } => {}
                Pdu::SerialQuery { .. } | Pdu::ResetQuery { .. } | Pdu::ErrorReport { .. } => {
                    bail!("cache sent a router-only PDU")
                }
            }
        }
    }

    async fn full_sync(&mut self) -> anyhow::Result<Snapshot> {
        let mut vrps = HashSet::new();
        let mut aspas = BTreeMap::new();
        let mut session = None;
        let q = Pdu::ResetQuery {
            version: self.version,
        };
        match self.sync(q, &mut vrps, &mut aspas, &mut session).await? {
            (SyncResult::Done, serial, timing) => Ok(Snapshot {
                vrps,
                aspas,
                session_id: session.unwrap_or(0),
                serial,
                timing: timing.unwrap_or(Timing::DEFAULT).clamped(),
                version: self.version,
            }),
            (SyncResult::CacheReset, ..) => bail!("cache answered a Reset Query with Cache Reset"),
        }
    }

    /// Incremental update; falls back to a full sync on Cache Reset.
    async fn incremental(&mut self, current: &Snapshot) -> anyhow::Result<Snapshot> {
        let mut vrps = current.vrps.clone();
        let mut aspas = current.aspas.clone();
        let mut session = Some(current.session_id);
        let q = Pdu::SerialQuery {
            version: self.version,
            session_id: current.session_id,
            serial: current.serial,
        };
        match self.sync(q, &mut vrps, &mut aspas, &mut session).await? {
            (SyncResult::Done, serial, timing) => Ok(Snapshot {
                vrps,
                aspas,
                session_id: current.session_id,
                serial,
                timing: timing.map(Timing::clamped).unwrap_or(current.timing),
                version: self.version,
            }),
            (SyncResult::CacheReset, ..) => {
                tracing::info!("cache reset requested, doing full resync");
                self.full_sync().await
            }
        }
    }
}

/// Connects, negotiates the version (starting at `version`, stepping down
/// on "unsupported version") and performs a full sync. Returns the open
/// connection for further updates.
async fn connect(target: &RtrTarget, version: &mut u8) -> anyhow::Result<(Conn, Snapshot)> {
    loop {
        let mut conn = Conn::open(target, *version).await?;
        match conn.full_sync().await {
            Ok(s) => return Ok((conn, s)),
            Err(e) if e.is::<VersionUnsupported>() && *version > 0 => {
                tracing::info!(
                    "cache does not speak RTR v{}, falling back to v{}",
                    *version,
                    *version - 1
                );
                *version -= 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// One-shot fetch of the complete payload set (used by the CLI).
pub async fn fetch(target: &RtrTarget) -> anyhow::Result<Snapshot> {
    let mut version = target.max_version;
    Ok(connect(target, &mut version).await?.1)
}

fn meta(s: &Snapshot) -> UpdateMeta {
    UpdateMeta {
        serial: Some(s.serial),
        session_id: Some(s.session_id),
        rtr_version: Some(s.version),
        expire_secs: u64::from(s.timing.expire),
    }
}

/// Long-running RTR session that keeps `state` up to date. Never returns.
pub async fn run(target: RtrTarget, state: Arc<AppState>) {
    let addr = target.to_string();
    let mut version = target.max_version;
    let mut retry = Duration::from_secs(u64::from(Timing::DEFAULT.retry));
    loop {
        match session(&target, &mut version, &state, &mut retry).await {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "RTR session to {addr} failed");
                state.record_error(&e);
            }
        }
        // shortcut: fixed retry interval from the cache (or 600s default), no jitter; add backoff if many routers share one cache.
        let wait = retry.min(Duration::from_secs(60));
        tracing::info!("reconnecting to {addr} in {}s", wait.as_secs());
        tokio::time::sleep(wait).await;
    }
}

async fn session(
    target: &RtrTarget,
    version: &mut u8,
    state: &AppState,
    retry: &mut Duration,
) -> anyhow::Result<()> {
    let (mut conn, mut snap) = connect(target, version).await?;
    tracing::info!(
        addr = %target,
        version = snap.version,
        session = snap.session_id,
        serial = snap.serial,
        "RTR session established"
    );
    *retry = Duration::from_secs(u64::from(snap.timing.retry));
    state.publish_data(snap.data(), meta(&snap));
    loop {
        let refresh = Duration::from_secs(u64::from(snap.timing.refresh));
        match conn.recv(Some(refresh)).await? {
            None | Some(Pdu::SerialNotify { .. }) => {}
            Some(Pdu::Ignored { .. }) => continue,
            Some(Pdu::ErrorReport { code, text, .. }) => {
                bail!("cache sent error report {code}: {text}")
            }
            Some(other) => bail!("unexpected PDU outside of a response: {other:?}"),
        }
        let next = conn.incremental(&snap).await?;
        *retry = Duration::from_secs(u64::from(next.timing.retry));
        let changed = next.vrps != snap.vrps || next.aspas != snap.aspas;
        snap = next;
        if changed || state.status().stale {
            state.publish_data(snap.data(), meta(&snap));
        } else {
            state.mark_fresh(meta(&snap));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtr::transport::TransportConfig;
    use tokio::net::{TcpListener, TcpStream};

    fn target(addr: &str, max_version: u8) -> RtrTarget {
        RtrTarget::new(addr, TransportConfig::default(), max_version).unwrap()
    }

    fn vrp(p: &str, max: u8, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), max, asn).unwrap()
    }

    async fn read_query(s: &mut TcpStream) -> Pdu {
        let mut h = [0u8; 8];
        s.read_exact(&mut h).await.unwrap();
        let len = pdu::header_length(&h).unwrap();
        let mut b = vec![0u8; len];
        b[..8].copy_from_slice(&h);
        s.read_exact(&mut b[8..]).await.unwrap();
        pdu::decode(&b).unwrap()
    }

    async fn send_all(s: &mut TcpStream, pdus: &[Pdu]) {
        let bytes: Vec<u8> = pdus.iter().flat_map(Pdu::encode).collect();
        s.write_all(&bytes).await.unwrap();
    }

    fn full_response(version: u8) -> Vec<Pdu> {
        vec![
            Pdu::CacheResponse {
                version,
                session_id: 9,
            },
            Pdu::Prefix {
                version,
                announce: true,
                vrp: vrp("192.0.2.0/24", 24, 64500),
            },
            Pdu::Prefix {
                version,
                announce: true,
                vrp: vrp("2001:db8::/32", 48, 64501),
            },
            Pdu::Ignored {
                version,
                pdu_type: pdu::TYPE_ROUTER_KEY,
            },
            Pdu::EndOfData {
                version,
                session_id: 9,
                serial: 5,
                timing: (version >= 1).then_some(Timing {
                    refresh: 900,
                    retry: 300,
                    expire: 3600,
                }),
            },
        ]
    }

    #[tokio::test]
    async fn fetch_v1() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 1 });
            // A Router Key PDU of real (variable) size must be skipped.
            let mut rk = vec![1u8, 9, 0, 0, 0, 0, 0, 16];
            rk.extend_from_slice(&[0u8; 8]);
            s.write_all(&rk).await.unwrap();
            send_all(&mut s, &full_response(1)).await;
        });
        let snap = fetch(&target(&addr, 1)).await.unwrap();
        assert_eq!(snap.version, 1);
        assert_eq!(snap.serial, 5);
        assert_eq!(snap.session_id, 9);
        assert_eq!(snap.timing.refresh, 900);
        assert_eq!(snap.timing.expire, 3600);
        assert_eq!(snap.vrps.len(), 2);
    }

    #[tokio::test]
    async fn falls_back_to_v0() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 1 });
            send_all(
                &mut s,
                &[Pdu::ErrorReport {
                    version: 0,
                    code: pdu::ERR_UNSUPPORTED_VERSION,
                    pdu: vec![],
                    text: String::new(),
                }],
            )
            .await;
            drop(s);
            let (mut s, _) = l.accept().await.unwrap();
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 0 });
            send_all(&mut s, &full_response(0)).await;
        });
        let snap = fetch(&target(&addr, 1)).await.unwrap();
        assert_eq!(snap.version, 0);
        assert_eq!(snap.timing, Timing::DEFAULT);
        assert_eq!(snap.vrps.len(), 2);
    }

    #[tokio::test]
    async fn incremental_and_cache_reset() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            read_query(&mut s).await;
            send_all(&mut s, &full_response(1)).await;
            // Incremental: withdraw one, announce one.
            assert_eq!(
                read_query(&mut s).await,
                Pdu::SerialQuery {
                    version: 1,
                    session_id: 9,
                    serial: 5
                }
            );
            send_all(
                &mut s,
                &[
                    Pdu::CacheResponse {
                        version: 1,
                        session_id: 9,
                    },
                    Pdu::Prefix {
                        version: 1,
                        announce: false,
                        vrp: vrp("192.0.2.0/24", 24, 64500),
                    },
                    Pdu::Prefix {
                        version: 1,
                        announce: true,
                        vrp: vrp("203.0.113.0/24", 24, 64502),
                    },
                    Pdu::EndOfData {
                        version: 1,
                        session_id: 9,
                        serial: 6,
                        timing: Some(Timing::DEFAULT),
                    },
                ],
            )
            .await;
            // Next serial query answered with Cache Reset, then full data.
            read_query(&mut s).await;
            send_all(&mut s, &[Pdu::CacheReset { version: 1 }]).await;
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 1 });
            send_all(&mut s, &full_response(1)).await;
        });
        let mut v = 1;
        let (mut conn, snap) = connect(&target(&addr, 1), &mut v).await.unwrap();
        let next = conn.incremental(&snap).await.unwrap();
        assert_eq!(next.serial, 6);
        assert!(next.vrps.contains(&vrp("203.0.113.0/24", 24, 64502)));
        assert!(!next.vrps.contains(&vrp("192.0.2.0/24", 24, 64500)));
        assert_eq!(next.vrps.len(), 2);
        let again = conn.incremental(&next).await.unwrap();
        assert_eq!(again.serial, 5);
        assert!(again.vrps.contains(&vrp("192.0.2.0/24", 24, 64500)));
    }

    #[tokio::test]
    async fn v2_aspa_with_fallback_from_v2() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 2 });
            let mut pdus = full_response(2);
            pdus.insert(
                1,
                Pdu::Aspa {
                    version: 2,
                    announce: true,
                    customer: 64500,
                    providers: vec![64510, 64511],
                },
            );
            send_all(&mut s, &pdus).await;
            // Incremental: withdraw the ASPA.
            read_query(&mut s).await;
            send_all(
                &mut s,
                &[
                    Pdu::CacheResponse {
                        version: 2,
                        session_id: 9,
                    },
                    Pdu::Aspa {
                        version: 2,
                        announce: false,
                        customer: 64500,
                        providers: vec![],
                    },
                    Pdu::EndOfData {
                        version: 2,
                        session_id: 9,
                        serial: 6,
                        timing: Some(Timing::DEFAULT),
                    },
                ],
            )
            .await;
        });
        let mut v = 2;
        let (mut conn, snap) = connect(&target(&addr, 2), &mut v).await.unwrap();
        assert_eq!(snap.version, 2);
        assert_eq!(snap.aspas[&64500], vec![64510, 64511]);
        assert_eq!(snap.data().aspas.len(), 1);
        let next = conn.incremental(&snap).await.unwrap();
        assert!(next.aspas.is_empty());

        // A v1-only cache: v2 -> v1 downgrade.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 2 });
            send_all(
                &mut s,
                &[Pdu::ErrorReport {
                    version: 1,
                    code: pdu::ERR_UNSUPPORTED_VERSION,
                    pdu: vec![],
                    text: String::new(),
                }],
            )
            .await;
            drop(s);
            let (mut s, _) = l.accept().await.unwrap();
            assert_eq!(read_query(&mut s).await, Pdu::ResetQuery { version: 1 });
            send_all(&mut s, &full_response(1)).await;
        });
        let snap = fetch(&target(&addr, 2)).await.unwrap();
        assert_eq!(snap.version, 1);
        assert!(snap.aspas.is_empty());
    }

    #[tokio::test]
    async fn oversized_pdu_drops_session() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            read_query(&mut s).await;
            let mut h = vec![1u8, 3, 0, 9];
            h.extend_from_slice(&u32::MAX.to_be_bytes());
            s.write_all(&h).await.unwrap();
            // Keep the socket open; the client must bail on the header alone.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let err = fetch(&target(&addr, 1)).await.unwrap_err();
        assert!(format!("{err:#}").contains("out of bounds"), "{err:#}");
    }
}
