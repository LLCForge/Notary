//! RTR transports: plain TCP (RFC 6810/8210, port 323), TLS (RFC 6810
//! section 7.2, port 324, rustls) and SSH (subsystem `rpki-rtr`, russh).
//!
//! Endpoints are written as `host:port`, `tcp://host:port`,
//! `tls://host[:port]` or `ssh://user@host[:port]`.

use std::fmt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_DEFAULT_PORT: u16 = 324;
const SSH_DEFAULT_PORT: u16 = 22;
/// SSH subsystem name from RFC 6810 section 7.1.
const SSH_SUBSYSTEM: &str = "rpki-rtr";

/// Any byte stream an RTR session can run over.
pub trait RtrStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> RtrStream for T {}

/// TLS / SSH settings (`[vrp.transport]` in the config; the same flags on
/// the CLI). Secrets are environment variable names.
#[derive(Debug, Clone, Default, Deserialize, clap::Args)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// tls://: PEM CA bundle to trust instead of the built-in Mozilla roots.
    #[arg(long)]
    pub tls_ca_file: Option<PathBuf>,
    /// tls://: name to verify in the cache certificate (default: the host).
    #[arg(long)]
    pub tls_server_name: Option<String>,
    /// tls://: PEM client certificate chain for mutual TLS.
    #[arg(long, requires = "tls_client_key")]
    pub tls_client_cert: Option<PathBuf>,
    /// tls://: PEM private key for the client certificate.
    #[arg(long, requires = "tls_client_cert")]
    pub tls_client_key: Option<PathBuf>,
    /// ssh://: OpenSSH private key (Ed25519 or ECDSA).
    #[arg(long)]
    pub ssh_key_file: Option<PathBuf>,
    /// ssh://: environment variable holding the key passphrase.
    #[arg(long)]
    pub ssh_key_passphrase_env: Option<String>,
    /// ssh://: environment variable holding a password (instead of a key).
    #[arg(long)]
    pub ssh_password_env: Option<String>,
    /// ssh://: pinned host key fingerprint, `SHA256:...` as printed by
    /// `ssh-keygen -lf`. Required: unknown host keys are refused.
    #[arg(long)]
    pub ssh_host_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(String),
    Tls {
        host: String,
        port: u16,
    },
    Ssh {
        user: String,
        host: String,
        port: u16,
    },
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Tcp(a) => write!(f, "rtr://{a}"),
            Endpoint::Tls { host, port } => write!(f, "tls://{}:{port}", bracket(host)),
            Endpoint::Ssh { user, host, port } => {
                write!(f, "ssh://{user}@{}:{port}", bracket(host))
            }
        }
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Splits `host[:port]` / `[v6][:port]`.
fn host_port(s: &str, default: Option<u16>) -> anyhow::Result<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("unclosed '['"))?;
        (h, tail.strip_prefix(':'))
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            _ => (s, None),
        }
    };
    if host.is_empty() || host.len() > 253 || host.contains(['/', '@', ' ']) {
        bail!("invalid host in {s:?}");
    }
    let port = match port {
        Some(p) => p.parse().map_err(|_| anyhow!("invalid port in {s:?}"))?,
        None => default.ok_or_else(|| anyhow!("{s:?} needs a port"))?,
    };
    Ok((host.to_string(), port))
}

impl Endpoint {
    pub fn parse(s: &str) -> anyhow::Result<Endpoint> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port) = host_port(rest, Some(TLS_DEFAULT_PORT))?;
            Ok(Endpoint::Tls { host, port })
        } else if let Some(rest) = s.strip_prefix("ssh://") {
            let (user, hp) = rest
                .split_once('@')
                .ok_or_else(|| anyhow!("ssh endpoint needs a user: ssh://user@host[:port]"))?;
            if user.is_empty() || user.len() > 64 {
                bail!("invalid ssh user");
            }
            let (host, port) = host_port(hp, Some(SSH_DEFAULT_PORT))?;
            Ok(Endpoint::Ssh {
                user: user.to_string(),
                host,
                port,
            })
        } else {
            let rest = s
                .strip_prefix("tcp://")
                .or_else(|| s.strip_prefix("rtr://"))
                .unwrap_or(s);
            let (host, port) = host_port(rest, None)?;
            Ok(Endpoint::Tcp(format!("{}:{port}", bracket(&host))))
        }
    }
}

/// A cache to connect to: where, how, and the highest RTR version to offer.
#[derive(Debug, Clone)]
pub struct RtrTarget {
    pub endpoint: Endpoint,
    pub transport: TransportConfig,
    pub max_version: u8,
}

impl RtrTarget {
    pub fn new(spec: &str, transport: TransportConfig, max_version: u8) -> anyhow::Result<Self> {
        let endpoint = Endpoint::parse(spec)?;
        if let Endpoint::Ssh { .. } = endpoint {
            if transport.ssh_host_key.is_none() {
                bail!("ssh:// needs ssh_host_key (SHA256:... fingerprint of the cache host key)");
            }
            if transport.ssh_key_file.is_none() && transport.ssh_password_env.is_none() {
                bail!("ssh:// needs ssh_key_file or ssh_password_env");
            }
        }
        if max_version > super::pdu::MAX_VERSION {
            bail!("RTR version {max_version} is not supported (max 2)");
        }
        Ok(RtrTarget {
            endpoint,
            transport,
            max_version,
        })
    }
}

impl fmt::Display for RtrTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.endpoint.fmt(f)
    }
}

/// Opens a byte stream to the cache.
pub async fn connect(target: &RtrTarget) -> anyhow::Result<Box<dyn RtrStream>> {
    let label = target.endpoint.to_string();
    let fut = async {
        let s: Box<dyn RtrStream> = match &target.endpoint {
            Endpoint::Tcp(addr) => {
                let s = TcpStream::connect(addr.as_str()).await?;
                s.set_nodelay(true)?;
                Box::new(s)
            }
            Endpoint::Tls { host, port } => {
                Box::new(tls_connect(host, *port, &target.transport).await?)
            }
            Endpoint::Ssh { user, host, port } => {
                Box::new(ssh_connect(user, host, *port, &target.transport).await?)
            }
        };
        anyhow::Ok(s)
    };
    timeout(CONNECT_TIMEOUT * 3, fut)
        .await
        .map_err(|_| anyhow!("connecting to {label} timed out"))?
        .with_context(|| format!("connecting to {label}"))
}

async fn tcp(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    let s = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow!("TCP connect timed out"))??;
    s.set_nodelay(true)?;
    Ok(s)
}

fn read_pem(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if meta.len() > 4 * 1024 * 1024 {
        bail!("{} is larger than 4 MiB", path.display());
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

pub fn tls_config(t: &TransportConfig) -> anyhow::Result<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let mut roots = rustls::RootCertStore::empty();
    match &t.tls_ca_file {
        Some(path) => {
            let pem = read_pem(path)?;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                roots
                    .add(cert.context("parsing CA certificate")?)
                    .context("adding CA certificate")?;
            }
            if roots.is_empty() {
                bail!("{} contains no certificates", path.display());
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .with_root_certificates(roots);
    Ok(match (&t.tls_client_cert, &t.tls_client_key) {
        (Some(c), Some(k)) => {
            let certs = CertificateDer::pem_slice_iter(&read_pem(c)?)
                .collect::<Result<Vec<_>, _>>()
                .context("parsing client certificate")?;
            let key = PrivateKeyDer::from_pem_slice(&read_pem(k)?).context("parsing client key")?;
            builder
                .with_client_auth_cert(certs, key)
                .context("client certificate")?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => bail!("tls_client_cert and tls_client_key must be set together"),
    })
}

async fn tls_connect(
    host: &str,
    port: u16,
    t: &TransportConfig,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let cfg = tls_config(t)?;
    let name = t.tls_server_name.as_deref().unwrap_or(host).to_string();
    let server_name = rustls::pki_types::ServerName::try_from(name)
        .map_err(|_| anyhow!("invalid TLS server name"))?;
    let stream = tcp(host, port).await?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(server_name, stream)
        .await
        .context("TLS handshake")?;
    Ok(tls)
}

/// Accepts only the pinned host key.
struct PinnedHostKey {
    fingerprint: String,
}

impl russh::client::Handler for PinnedHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                let fp = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
                let ok = fp == self.fingerprint;
                if !ok {
                    tracing::error!(presented = %fp, "SSH host key does not match ssh_host_key");
                }
                ok
            }
            russh::keys::PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

/// SSH channel stream that keeps its session alive.
pub struct SshStream {
    stream: russh::ChannelStream<russh::client::Msg>,
    _session: russh::client::Handle<PinnedHostKey>,
}

impl AsyncRead for SshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn ssh_connect(
    user: &str,
    host: &str,
    port: u16,
    t: &TransportConfig,
) -> anyhow::Result<SshStream> {
    let fingerprint = t
        .ssh_host_key
        .clone()
        .ok_or_else(|| anyhow!("ssh_host_key is required"))?;
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(60)),
        ..Default::default()
    });
    let stream = tcp(host, port).await?;
    let mut session = russh::client::connect_stream(config, stream, PinnedHostKey { fingerprint })
        .await
        .context("SSH handshake (is ssh_host_key correct?)")?;
    let auth = match (&t.ssh_key_file, &t.ssh_password_env) {
        (Some(path), _) => {
            let pass = t
                .ssh_key_passphrase_env
                .as_deref()
                .map(llcforge_beacon::env_secret)
                .transpose()?;
            let key = russh::keys::load_secret_key(path, pass.as_deref())
                .with_context(|| format!("loading SSH key {}", path.display()))?;
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
            session.authenticate_publickey(user, key).await?
        }
        (None, Some(var)) => {
            session
                .authenticate_password(user, llcforge_beacon::env_secret(var)?)
                .await?
        }
        (None, None) => bail!("ssh_key_file or ssh_password_env is required"),
    };
    if !auth.success() {
        bail!("SSH authentication as {user} was rejected");
    }
    let mut channel = session.channel_open_session().await?;
    channel.request_subsystem(true, SSH_SUBSYSTEM).await?;
    loop {
        match timeout(CONNECT_TIMEOUT, channel.wait()).await {
            Err(_) => bail!("no reply to the {SSH_SUBSYSTEM} subsystem request"),
            Ok(Some(russh::ChannelMsg::Success)) => break,
            Ok(Some(russh::ChannelMsg::Failure)) | Ok(None) => {
                bail!("cache refused the {SSH_SUBSYSTEM} subsystem")
            }
            Ok(Some(_)) => {}
        }
    }
    Ok(SshStream {
        stream: channel.into_stream(),
        _session: session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(
            Endpoint::parse("192.0.2.10:3323").unwrap(),
            Endpoint::Tcp("192.0.2.10:3323".into())
        );
        assert_eq!(
            Endpoint::parse("tcp://[2001:db8::1]:323").unwrap(),
            Endpoint::Tcp("[2001:db8::1]:323".into())
        );
        assert_eq!(
            Endpoint::parse("tls://rpki.example.net").unwrap(),
            Endpoint::Tls {
                host: "rpki.example.net".into(),
                port: 324
            }
        );
        assert_eq!(
            Endpoint::parse("ssh://rtr@[2001:db8::2]:2222").unwrap(),
            Endpoint::Ssh {
                user: "rtr".into(),
                host: "2001:db8::2".into(),
                port: 2222
            }
        );
        assert!(Endpoint::parse("192.0.2.10").is_err());
        assert!(Endpoint::parse("ssh://host:22").is_err());
        assert!(Endpoint::parse("tls://:99").is_err());
        assert!(Endpoint::parse("tls://h:99999").is_err());
        assert_eq!(
            Endpoint::parse("ssh://rtr@h").unwrap().to_string(),
            "ssh://rtr@h:22"
        );
    }

    #[test]
    fn ssh_target_requires_pinning() {
        let t = TransportConfig {
            ssh_key_file: Some("k".into()),
            ..Default::default()
        };
        assert!(RtrTarget::new("ssh://rtr@h", t.clone(), 1).is_err());
        let t = TransportConfig {
            ssh_host_key: Some("SHA256:x".into()),
            ..t
        };
        assert!(RtrTarget::new("ssh://rtr@h", t, 1).is_ok());
        assert!(RtrTarget::new("h:1", TransportConfig::default(), 3).is_err());
    }

    #[test]
    fn tls_config_defaults_and_bad_ca() {
        assert!(tls_config(&TransportConfig::default()).is_ok());
        let t = TransportConfig {
            tls_ca_file: Some(PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/Cargo.toml"
            ))),
            ..Default::default()
        };
        assert!(tls_config(&t).is_err());
    }
}
