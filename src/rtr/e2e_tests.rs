//! End-to-end RTR over TLS and SSH against in-process servers using the
//! test-only keys in `testdata/` (never use them anywhere else).

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::client::fetch;
use super::pdu::{self, Pdu, Timing};
use super::transport::{RtrTarget, TransportConfig};
use crate::vrp::Vrp;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/rtr/testdata")
        .join(name)
}

/// Minimal cache: answers one Reset Query with one VRP.
async fn serve_rtr<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut h = [0u8; 8];
    s.read_exact(&mut h).await.unwrap();
    let len = pdu::header_length(&h).unwrap();
    let mut b = vec![0u8; len];
    b[..8].copy_from_slice(&h);
    s.read_exact(&mut b[8..]).await.unwrap();
    assert_eq!(pdu::decode(&b).unwrap(), Pdu::ResetQuery { version: 1 });
    let vrp = Vrp::new("192.0.2.0/24".parse().unwrap(), 24, 64500).unwrap();
    let out: Vec<u8> = [
        Pdu::CacheResponse {
            version: 1,
            session_id: 3,
        },
        Pdu::Prefix {
            version: 1,
            announce: true,
            vrp,
        },
        Pdu::EndOfData {
            version: 1,
            session_id: 3,
            serial: 77,
            timing: Some(Timing::DEFAULT),
        },
    ]
    .iter()
    .flat_map(Pdu::encode)
    .collect();
    s.write_all(&out).await.unwrap();
    s.flush().await.unwrap();
    // Keep the stream open until the client is done.
    let _ = s.read(&mut h).await;
}

#[tokio::test]
async fn rtr_over_tls() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = CertificateDer::pem_file_iter(testdata("server.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(testdata("server.key")).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Second connection: the untrusted-CA attempt below.
        for _ in 0..2 {
            let (s, _) = l.accept().await.unwrap();
            if let Ok(tls) = acceptor.accept(s).await {
                serve_rtr(tls).await;
            }
        }
    });

    let t = TransportConfig {
        tls_ca_file: Some(testdata("ca.pem")),
        tls_server_name: Some("localhost".into()),
        ..Default::default()
    };
    let target = RtrTarget::new(&format!("tls://127.0.0.1:{port}"), t, 1).unwrap();
    let snap = fetch(&target).await.unwrap();
    assert_eq!(snap.serial, 77);
    assert_eq!(snap.vrps.len(), 1);

    // Default (public) roots must not trust the test CA.
    let t = TransportConfig {
        tls_server_name: Some("localhost".into()),
        ..Default::default()
    };
    let target = RtrTarget::new(&format!("tls://127.0.0.1:{port}"), t, 1).unwrap();
    assert!(fetch(&target).await.is_err());
}

struct TestSshServer {
    channel: Option<russh::Channel<russh::server::Msg>>,
    client_key: russh::keys::PublicKey,
}

impl russh::server::Handler for TestSshServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(
            if user == "rtr" && key.public_key.key_data() == self.client_key.key_data() {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            },
        )
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.channel = Some(channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        match (name, self.channel.take()) {
            ("rpki-rtr", Some(ch)) => {
                session.channel_success(id)?;
                tokio::spawn(serve_rtr(ch.into_stream()));
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }
}

#[tokio::test]
async fn rtr_over_ssh() {
    let host = russh::keys::load_secret_key(testdata("host_ed25519"), None).unwrap();
    let fingerprint = host
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    let client = russh::keys::load_secret_key(testdata("client_ed25519"), None).unwrap();
    let config = Arc::new(russh::server::Config {
        keys: vec![host],
        ..Default::default()
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let client_key = client.public_key().clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (s, _) = l.accept().await.unwrap();
            let h = TestSshServer {
                channel: None,
                client_key: client_key.clone(),
            };
            if let Ok(running) = russh::server::run_stream(config.clone(), s, h).await {
                tokio::spawn(running);
            }
        }
    });

    let t = TransportConfig {
        ssh_key_file: Some(testdata("client_ed25519")),
        ssh_host_key: Some(fingerprint),
        ..Default::default()
    };
    let target = RtrTarget::new(&format!("ssh://rtr@127.0.0.1:{port}"), t.clone(), 1).unwrap();
    let snap = fetch(&target).await.unwrap();
    assert_eq!(snap.serial, 77);
    assert_eq!(snap.vrps.len(), 1);

    // A wrong pinned fingerprint is refused before authentication.
    let t = TransportConfig {
        ssh_host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
        ..t
    };
    let target = RtrTarget::new(&format!("ssh://rtr@127.0.0.1:{port}"), t, 1).unwrap();
    assert!(fetch(&target).await.is_err());
}
