//! TOML configuration for `notary run`, validated at startup.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use llcforge_beacon::{AlertsConfig, HealthConfig, SilencesConfig};
use serde::Deserialize;

use crate::prefix::{Asn, Prefix};
use crate::rtr::transport::{RtrTarget, TransportConfig};
use crate::slurm::Slurm;
use crate::sources::{self, PrefixSource};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Queue, silences, watch state and VRP history. Default: platform
    /// data directory (`STATE_DIRECTORY` under systemd).
    pub data_dir: Option<PathBuf>,
    pub vrp: VrpConfig,
    #[serde(default)]
    pub watch: Vec<WatchEntry>,
    #[serde(default)]
    pub watch_as: Vec<WatchAs>,
    #[serde(default)]
    pub ripestat: RipeStatConfig,
    #[serde(default)]
    pub prefix_sources: PrefixSourcesConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub history: HistoryConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub silences: SilencesConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrpConfig {
    /// RTR cache: `host:port`, `tls://host[:port]` or `ssh://user@host[:port]`.
    pub rtr: Option<String>,
    /// JSON export path or `http(s)://` URL.
    pub json: Option<String>,
    /// Highest RTR version to offer (2 enables ASPA); steps down automatically.
    #[serde(default = "default_rtr_version")]
    pub rtr_max_version: u8,
    /// TLS / SSH settings for `tls://` and `ssh://` caches.
    #[serde(default)]
    pub transport: TransportConfig,
    /// JSON source only: reload interval in seconds.
    #[serde(default = "default_json_refresh")]
    pub json_refresh_secs: u64,
    /// JSON source only: data is reported stale after this many seconds
    /// without a successful reload. RTR uses the cache's expire interval.
    #[serde(default = "default_json_expire")]
    pub json_expire_secs: u64,
    /// RFC 8416 SLURM files applied on top of the source.
    #[serde(default)]
    pub slurm: Vec<PathBuf>,
    /// Warn when every ROA making a watched route Valid expires within this
    /// many days (needs expiry data: rpki-client JSON or Routinator jsonext).
    /// 0 disables.
    #[serde(default = "default_expiry_warn")]
    pub expiry_warn_days: u64,
}

fn default_rtr_version() -> u8 {
    1
}

fn default_json_refresh() -> u64 {
    600
}

fn default_json_expire() -> u64 {
    7200
}

fn default_expiry_warn() -> u64 {
    7
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchEntry {
    pub prefix: Prefix,
    pub origin: Asn,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchAs {
    pub asn: Asn,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RipeStatConfig {
    /// Refresh interval for every prefix source.
    #[serde(default = "default_ripestat_refresh")]
    pub refresh_secs: u64,
    #[serde(default = "default_max_prefixes")]
    pub max_prefixes_per_as: usize,
}

impl Default for RipeStatConfig {
    fn default() -> Self {
        RipeStatConfig {
            refresh_secs: default_ripestat_refresh(),
            max_prefixes_per_as: default_max_prefixes(),
        }
    }
}

fn default_ripestat_refresh() -> u64 {
    3600
}

fn default_max_prefixes() -> usize {
    10_000
}

/// Where `[[watch_as]]` prefix lists come from (the union of all enabled).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PrefixSourcesConfig {
    pub ripestat: bool,
    /// Pathology API base URL, e.g. `http://127.0.0.1:8180`.
    pub pathology_url: Option<String>,
    pub pathology_token_env: Option<String>,
    pub bgptools: bool,
    /// Required by bgp.tools: who you are and a contact.
    pub bgptools_user_agent: Option<String>,
}

impl Default for PrefixSourcesConfig {
    fn default() -> Self {
        PrefixSourcesConfig {
            ripestat: true,
            pathology_url: None,
            pathology_token_env: None,
            bgptools: false,
            bgptools_user_agent: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApiConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Bearer token for `/v1/*` and the web UI data calls (env var name).
    /// Health probes and `/metrics` stay open.
    pub token_env: Option<String>,
    /// Serve the embedded web UI at `/`.
    pub ui: bool,
    /// Largest `POST /v1/validity` batch.
    pub max_batch: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            enabled: true,
            listen: SocketAddr::from(([127, 0, 0, 1], 8323)),
            token_env: None,
            ui: true,
            max_batch: 10_000,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HistoryConfig {
    pub enabled: bool,
    /// The log is rotated to `.1` at this size (two files are kept).
    pub max_bytes: u64,
    /// VRPs itemised per event; the counts are always exact.
    pub max_listed: usize,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        HistoryConfig {
            enabled: true,
            max_bytes: 64 * 1024 * 1024,
            max_listed: 10_000,
        }
    }
}

pub enum VrpSource {
    Rtr(Box<RtrTarget>),
    Json(String),
}

/// Translates the pre-0.2 `[alerts]` keys (`webhook_url_env`,
/// `telegram_token_env`, `telegram_chat_id`) into `[[alerts.sink]]` entries.
fn migrate_legacy_alerts(root: &mut toml::Table) -> anyhow::Result<()> {
    let Some(toml::Value::Table(alerts)) = root.get_mut("alerts") else {
        return Ok(());
    };
    let webhook = alerts.remove("webhook_url_env");
    let tg_token = alerts.remove("telegram_token_env");
    let tg_chat = alerts.remove("telegram_chat_id");
    if webhook.is_none() && tg_token.is_none() && tg_chat.is_none() {
        return Ok(());
    }
    if tg_token.is_some() != tg_chat.is_some() {
        bail!("alerts.telegram_token_env and alerts.telegram_chat_id must be set together");
    }
    let mut sinks = Vec::new();
    if let Some(var) = webhook {
        let mut t = toml::Table::new();
        t.insert("type".into(), "webhook".into());
        t.insert("url_env".into(), var);
        sinks.push(toml::Value::Table(t));
    }
    if let (Some(var), Some(chat)) = (tg_token, tg_chat) {
        let mut t = toml::Table::new();
        t.insert("type".into(), "telegram".into());
        t.insert("bot_token_env".into(), var);
        t.insert("chat_id".into(), chat);
        sinks.push(toml::Value::Table(t));
    }
    tracing::warn!("[alerts] webhook_url_env / telegram_* are deprecated; use [[alerts.sink]]");
    match alerts
        .entry("sink")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
    {
        toml::Value::Array(a) => a.extend(sinks),
        _ => bail!("alerts.sink must be an array of tables"),
    }
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("config {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Config> {
        let mut root: toml::Table = toml::from_str(text).context("parsing TOML")?;
        migrate_legacy_alerts(&mut root)?;
        let cfg: Config = toml::Value::Table(root).try_into()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.source()?;
        if self.vrp.json_refresh_secs < 10 {
            bail!("vrp.json_refresh_secs must be at least 10");
        }
        if self.vrp.json_expire_secs < self.vrp.json_refresh_secs {
            bail!("vrp.json_expire_secs must not be lower than vrp.json_refresh_secs");
        }
        if self.vrp.expiry_warn_days > 3650 {
            bail!("vrp.expiry_warn_days must be at most 3650");
        }
        if self.ripestat.refresh_secs < 60 {
            bail!("ripestat.refresh_secs must be at least 60");
        }
        if self.ripestat.max_prefixes_per_as == 0 || self.ripestat.max_prefixes_per_as > 1_000_000 {
            bail!("ripestat.max_prefixes_per_as must be between 1 and 1000000");
        }
        if self.watch.is_empty() && self.watch_as.is_empty() && !self.api.enabled {
            bail!("nothing to do: no [[watch]], no [[watch_as]] and the API is disabled");
        }
        if self.api.max_batch == 0 || self.api.max_batch > 100_000 {
            bail!("api.max_batch must be between 1 and 100000");
        }
        if self.history.max_bytes < 4096 || self.history.max_listed == 0 {
            bail!("history.max_bytes must be >= 4096 and history.max_listed >= 1");
        }
        let srcs = self.prefix_sources()?;
        if !self.watch_as.is_empty() && srcs.is_empty() {
            bail!("[[watch_as]] needs at least one enabled [prefix_sources] entry");
        }
        Slurm::load(&self.vrp.slurm)?;
        Ok(())
    }

    pub fn source(&self) -> anyhow::Result<VrpSource> {
        match (&self.vrp.rtr, &self.vrp.json) {
            (Some(r), None) if !r.trim().is_empty() => Ok(VrpSource::Rtr(Box::new(
                RtrTarget::new(r, self.vrp.transport.clone(), self.vrp.rtr_max_version)?,
            ))),
            (None, Some(j)) if !j.trim().is_empty() => Ok(VrpSource::Json(j.clone())),
            _ => bail!("set exactly one of vrp.rtr or vrp.json"),
        }
    }

    /// Enabled prefix sources; secrets are read from the environment.
    pub fn prefix_sources(&self) -> anyhow::Result<Vec<PrefixSource>> {
        let p = &self.prefix_sources;
        let mut out = Vec::new();
        if p.ripestat {
            out.push(PrefixSource::RipeStat);
        }
        if let Some(url) = &p.pathology_url {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                bail!("prefix_sources.pathology_url must start with http:// or https://");
            }
            let token = p
                .pathology_token_env
                .as_deref()
                .map(llcforge_beacon::env_secret)
                .transpose()?;
            out.push(PrefixSource::Pathology {
                url: url.trim_end_matches('/').to_string(),
                token,
            });
        }
        if p.bgptools {
            if self.ripestat.refresh_secs < sources::BGPTOOLS_MIN_INTERVAL_SECS {
                bail!(
                    "bgp.tools must not be fetched more often than every {}s: raise ripestat.refresh_secs",
                    sources::BGPTOOLS_MIN_INTERVAL_SECS
                );
            }
            out.push(PrefixSource::BgpTools {
                user_agent: sources::validate_user_agent(
                    p.bgptools_user_agent.as_deref().unwrap_or_default(),
                )?,
            });
        }
        Ok(out)
    }

    /// Fingerprint of the VRP source settings (these need a restart).
    pub fn source_spec(&self) -> String {
        let v = &self.vrp;
        format!(
            "{:?}|{:?}|{}|{:?}|{}|{}",
            v.rtr, v.json, v.rtr_max_version, v.transport, v.json_refresh_secs, v.json_expire_secs
        )
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| llcforge_beacon::default_data_dir(crate::state::TOOL))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use llcforge_beacon::config::SinkKind;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../notary.example.toml");
        let c: Config = toml::from_str(text).unwrap();
        assert!(matches!(c.source().unwrap(), VrpSource::Json(_)));
        assert_eq!(c.watch.len(), 3);
        assert_eq!(c.watch_as[0].asn, Asn(64501));
        assert!(!c.alerts.sinks.is_empty());
    }

    #[test]
    fn helm_default_config_parses() {
        let values = include_str!("../deploy/helm/notary/values.yaml");
        let body: String = values
            .split("config: |")
            .nth(1)
            .unwrap()
            .lines()
            .skip(1)
            .take_while(|l| l.is_empty() || l.starts_with("  "))
            .map(|l| format!("{}\n", l.strip_prefix("  ").unwrap_or(l)))
            .collect();
        let c = Config::parse(&body).unwrap();
        assert_eq!(c.api.listen.to_string(), "0.0.0.0:8323");
    }

    #[test]
    fn minimal_rtr() {
        let c = Config::parse("[vrp]\nrtr = \"192.0.2.10:3323\"\n").unwrap();
        assert!(matches!(c.source().unwrap(), VrpSource::Rtr(_)));
        assert!(c.api.enabled);
        assert_eq!(c.api.listen.to_string(), "127.0.0.1:8323");
        assert_eq!(c.vrp.rtr_max_version, 1);
        assert!(c.history.enabled);
    }

    #[test]
    fn rejects_bad_configs() {
        let parse = Config::parse;
        assert!(parse("[vrp]\n").is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\njson = \"b\"\n").is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\nbogus = 1\n").is_err());
        assert!(parse(
            "[vrp]\nrtr = \"a:1\"\n[[watch]]\nprefix = \"192.0.2.1/24\"\norigin = 64500\n"
        )
        .is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\n[alerts]\ntelegram_chat_id = \"1\"\n").is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\n[api]\nenabled = false\n").is_err());
        assert!(parse("[vrp]\nrtr = \"ssh://u@h\"\n").is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\nrtr_max_version = 3\n").is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\nslurm = [\"/nonexistent.json\"]\n").is_err());
        assert!(parse("[vrp]\nrtr = \"a:1\"\n[prefix_sources]\nbgptools = true\n").is_err());
        assert!(parse(
            "[vrp]\nrtr = \"a:1\"\n[ripestat]\nrefresh_secs = 600\n[prefix_sources]\nbgptools = true\nbgptools_user_agent = \"example-noc - noc@example.net\"\n"
        )
        .is_err(), "refresh below 1800s");
        assert!(parse(
            "[vrp]\nrtr = \"a:1\"\n[ripestat]\nrefresh_secs = 3600\n[prefix_sources]\nbgptools = true\nbgptools_user_agent = \"example-noc - noc@example.net\"\n"
        )
        .is_ok());
        assert!(parse(
            "[vrp]\nrtr = \"a:1\"\n[prefix_sources]\nripestat = false\n[[watch_as]]\nasn = 1\n"
        )
        .is_err());
        assert!(
            parse("[vrp]\nrtr = \"a:1\"\n[prefix_sources]\npathology_url = \"ftp://x\"\n").is_err()
        );
    }

    #[test]
    fn legacy_alert_keys_become_sinks() {
        let c = Config::parse(
            "[vrp]\nrtr = \"a:1\"\n[alerts]\nwebhook_url_env = \"HOOK\"\n\
             telegram_token_env = \"TG\"\ntelegram_chat_id = \"-100123\"\n\
             [[alerts.sink]]\ntype = \"stdout\"\n",
        )
        .unwrap();
        let kinds: Vec<&str> = c.alerts.sinks.iter().map(|s| s.kind.type_name()).collect();
        assert_eq!(kinds, vec!["stdout", "webhook", "telegram"]);
        match &c.alerts.sinks[2].kind {
            SinkKind::Telegram(t) => assert_eq!(t.chat_id, "-100123"),
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn missing_sink_secret_fails_dispatcher_start() {
        let c = Config::parse(
            "[vrp]\nrtr = \"a:1\"\n[alerts]\nwebhook_url_env = \"NOTARY_TEST_SURELY_UNSET_VAR\"\n",
        )
        .unwrap();
        let r = llcforge_beacon::Dispatcher::start(
            &c.alerts,
            llcforge_beacon::DispatcherOptions {
                tool: "notary".into(),
                ..Default::default()
            },
        );
        assert!(r.is_err());
    }
}
