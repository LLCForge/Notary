//! Watcher: re-validates watched routes on every VRP change and prefix
//! source refresh, alerts on state transitions and on ROAs about to expire,
//! and persists its view so a restart neither re-alerts nor misses changes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use llcforge_beacon::Severity;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::prefix::Prefix;
use crate::sources::{self, PrefixSource};
use crate::state::{alert, AppState};
use crate::validator::{matches, validate, Validity};

/// Persisted watch state larger than this is ignored (start fresh).
const MAX_STATE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Route {
    pub prefix: Prefix,
    pub origin: u32,
}

#[derive(Serialize, Deserialize)]
struct SavedRoute {
    #[serde(flatten)]
    route: Route,
    validity: Validity,
}

#[derive(Default, Serialize, Deserialize)]
struct SavedState {
    version: u32,
    routes: Vec<SavedRoute>,
    #[serde(default)]
    expiring: Vec<Route>,
}

pub struct Watcher {
    state: Arc<AppState>,
    client: reqwest::Client,
    static_routes: Vec<Route>,
    watch_as: Vec<u32>,
    sources: Vec<PrefixSource>,
    refresh: Duration,
    max_prefixes: usize,
    expiry_warn_secs: i64,
    state_path: Option<PathBuf>,
    /// Last good prefix list per (source index, AS); kept when a fetch fails.
    as_prefixes: HashMap<(usize, u32), Vec<Prefix>>,
    last: BTreeMap<Route, Validity>,
    expiring: BTreeSet<Route>,
}

impl Watcher {
    pub fn new(
        cfg: &Config,
        state: Arc<AppState>,
        client: reqwest::Client,
        state_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let mut w = Watcher {
            state,
            client,
            static_routes: cfg
                .watch
                .iter()
                .map(|w| Route {
                    prefix: w.prefix,
                    origin: w.origin.0,
                })
                .collect(),
            watch_as: cfg.watch_as.iter().map(|w| w.asn.0).collect(),
            sources: cfg.prefix_sources()?,
            refresh: Duration::from_secs(cfg.ripestat.refresh_secs),
            max_prefixes: cfg.ripestat.max_prefixes_per_as,
            expiry_warn_secs: i64::try_from(cfg.vrp.expiry_warn_days * 86_400).unwrap_or(i64::MAX),
            state_path,
            as_prefixes: HashMap::new(),
            last: BTreeMap::new(),
            expiring: BTreeSet::new(),
        };
        w.load();
        Ok(w)
    }

    pub fn is_empty(&self) -> bool {
        self.static_routes.is_empty() && self.watch_as.is_empty()
    }

    fn load(&mut self) {
        let Some(path) = &self.state_path else {
            return;
        };
        match read_state(path) {
            Ok(Some(s)) => {
                self.last = s
                    .routes
                    .into_iter()
                    .map(|r| (r.route, r.validity))
                    .collect();
                self.expiring = s.expiring.into_iter().collect();
                tracing::info!(routes = self.last.len(), path = %path.display(), "watch state restored");
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), path = %path.display(), "ignoring unreadable watch state")
            }
        }
    }

    fn save(&self) {
        let Some(path) = &self.state_path else {
            return;
        };
        let s = SavedState {
            version: 1,
            routes: self
                .last
                .iter()
                .map(|(r, v)| SavedRoute {
                    route: *r,
                    validity: *v,
                })
                .collect(),
            expiring: self.expiring.iter().copied().collect(),
        };
        if let Err(e) = write_atomic(path, &s) {
            tracing::error!(error = %format!("{e:#}"), path = %path.display(), "saving watch state failed");
        }
    }

    pub async fn run(mut self) {
        let mut changes = self.state.subscribe();
        let mut refresh = tokio::time::interval(self.refresh);
        if self.state.status().loaded {
            self.evaluate();
        }
        loop {
            tokio::select! {
                r = changes.changed() => {
                    if r.is_err() {
                        return;
                    }
                }
                _ = refresh.tick(), if !self.watch_as.is_empty() => self.refresh_as().await,
            }
            if self.state.status().loaded {
                self.evaluate();
            }
        }
    }

    async fn refresh_as(&mut self) {
        for (i, src) in self.sources.clone().iter().enumerate() {
            match sources::fetch(&self.client, src, &self.watch_as, self.max_prefixes).await {
                Ok(map) => {
                    for (asn, (p, _)) in map {
                        tracing::info!(asn, prefixes = p.len(), source = %src, "prefix list refreshed");
                        self.as_prefixes.insert((i, asn), p);
                    }
                }
                Err(e) => {
                    let m = &self.state.metrics;
                    m.prefix_source_errors.fetch_add(1, Ordering::Relaxed);
                    if *src == PrefixSource::RipeStat {
                        m.ripestat_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::warn!(source = %src, error = %format!("{e:#}"), "prefix source fetch failed; keeping last list");
                }
            }
        }
    }

    fn routes(&self) -> Vec<Route> {
        let mut routes = self.static_routes.clone();
        for ((_, asn), prefixes) in &self.as_prefixes {
            routes.extend(prefixes.iter().map(|&prefix| Route {
                prefix,
                origin: *asn,
            }));
        }
        routes.sort_unstable();
        routes.dedup();
        routes
    }

    /// Validates every watched route and alerts on transitions. A route seen
    /// for the first time alerts only if it is Invalid.
    pub fn evaluate(&mut self) {
        self.evaluate_at(chrono::Utc::now().timestamp());
    }

    fn evaluate_at(&mut self, now: i64) {
        let table = self.state.table();
        let mut next = BTreeMap::new();
        let mut expiring = BTreeSet::new();
        let (mut valid, mut invalid, mut not_found) = (0, 0, 0);
        for route in self.routes() {
            let v = validate(&table, &route.prefix, route.origin);
            match v.validity {
                Validity::Valid => valid += 1,
                Validity::Invalid(_) => invalid += 1,
                Validity::NotFound => not_found += 1,
            }
            let previous = self.last.get(&route).copied();
            let alert_needed = match previous {
                Some(p) => p != v.validity,
                None => matches!(v.validity, Validity::Invalid(_)),
            };
            if alert_needed {
                let was = previous.map_or_else(|| "unknown".to_string(), |p| p.to_string());
                let severity = match v.validity {
                    Validity::Invalid(_) => Severity::Critical,
                    Validity::NotFound => Severity::Warning,
                    Validity::Valid => Severity::Info,
                };
                let mut a = alert(
                    "state_change",
                    severity,
                    format!(
                        "{} origin AS{}: {} -> {}",
                        route.prefix, route.origin, was, v.validity
                    ),
                )
                .resource(format!("{} AS{}", route.prefix, route.origin))
                .field("prefix", route.prefix)
                .field("origin", format!("AS{}", route.origin))
                .field("previous", was)
                .field("current", v.validity)
                .link(
                    "RIPEstat",
                    format!("https://stat.ripe.net/{}", route.prefix),
                )
                .resolved(v.validity == Validity::Valid);
                for c in v.covering.iter().take(10) {
                    a = a.field(
                        "covering_vrp",
                        format!("{} max /{} AS{}", c.prefix, c.max_length, c.asn),
                    );
                }
                self.state.alert(a);
            }
            if v.validity == Validity::Valid && self.expiry_warn_secs > 0 {
                // The route stays Valid until the last authorising VRP expires.
                let exp: Option<Option<i64>> = v
                    .covering
                    .iter()
                    .filter(|c| matches(c, &route.prefix, route.origin))
                    .map(|c| table.expires(c))
                    .max_by_key(|e| e.unwrap_or(i64::MAX));
                if let Some(Some(exp)) = exp {
                    if exp - now < self.expiry_warn_secs {
                        expiring.insert(route);
                        if !self.expiring.contains(&route) {
                            let when = chrono::DateTime::from_timestamp(exp, 0)
                                .map_or_else(|| exp.to_string(), |t| t.to_rfc3339());
                            self.state.alert(
                                alert(
                                    "roa_expiring",
                                    Severity::Warning,
                                    format!(
                                        "ROA for {} origin AS{} expires {when}",
                                        route.prefix, route.origin
                                    ),
                                )
                                .resource(format!("{} AS{}", route.prefix, route.origin))
                                .summary("Every ROA that makes this route Valid expires soon; renew it or the route becomes NotFound/Invalid.")
                                .field("expires", when),
                            );
                        }
                    }
                }
            }
            next.insert(route, v.validity);
        }
        for r in self.expiring.difference(&expiring) {
            if next.contains_key(r) {
                self.state.alert(
                    alert(
                        "roa_expiring",
                        Severity::Warning,
                        format!(
                            "ROA for {} origin AS{} renewed or replaced",
                            r.prefix, r.origin
                        ),
                    )
                    .resource(format!("{} AS{}", r.prefix, r.origin))
                    .resolved(true),
                );
            }
        }
        let changed = next != self.last || expiring != self.expiring;
        self.last = next;
        self.expiring = expiring;
        if changed {
            self.save();
        }
        let m = &self.state.metrics;
        m.watch_valid.store(valid, Ordering::Relaxed);
        m.watch_invalid.store(invalid, Ordering::Relaxed);
        m.watch_not_found.store(not_found, Ordering::Relaxed);
        m.watch_roa_expiring
            .store(self.expiring.len() as u64, Ordering::Relaxed);
        tracing::debug!(valid, invalid, not_found, "watch list evaluated");
    }
}

fn read_state(path: &Path) -> anyhow::Result<Option<SavedState>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if meta.len() > MAX_STATE_BYTES {
        anyhow::bail!("watch state larger than {MAX_STATE_BYTES} bytes");
    }
    let s: SavedState = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(Some(s))
}

/// Write to a temporary file, then rename, so a crash never leaves a torn file.
pub fn write_atomic<T: Serialize>(path: &Path, v: &T) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        serde_json::to_writer(&mut f, v)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{test_state, UpdateMeta};
    use crate::vrp::{Vrp, VrpData};

    const META: UpdateMeta = UpdateMeta {
        serial: None,
        session_id: None,
        rtr_version: None,
        expire_secs: 7200,
    };

    fn cfg() -> Config {
        Config::parse(
            "[vrp]\njson = \"x\"\n[[watch]]\nprefix = \"192.0.2.0/24\"\norigin = 64500\n\
             [[watch]]\nprefix = \"198.51.100.0/24\"\norigin = 64500\n",
        )
        .unwrap()
    }

    fn vrp(p: &str, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), 24, asn).unwrap()
    }

    #[test]
    fn alerts_on_transitions_and_persists() {
        let dir = std::env::temp_dir().join(format!("notary-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("watch-state.json");
        let state = Arc::new(test_state());
        let metrics = state.metrics.clone();
        let mut w = Watcher::new(
            &cfg(),
            state.clone(),
            reqwest::Client::new(),
            Some(path.clone()),
        )
        .unwrap();

        state.publish(
            [vrp("192.0.2.0/24", 64500), vrp("198.51.100.0/24", 64501)],
            META,
        );
        w.evaluate();
        // Only the initially Invalid route alerts.
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.watch_valid.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.watch_invalid.load(Ordering::Relaxed), 1);

        w.evaluate();
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 1);
        assert!(path.exists());

        // A restarted watcher remembers: no re-alert for the Invalid route...
        let mut w2 = Watcher::new(
            &cfg(),
            state.clone(),
            reqwest::Client::new(),
            Some(path.clone()),
        )
        .unwrap();
        w2.evaluate();
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 1);

        // ...and a change while it was down is caught: Valid -> NotFound.
        state.publish([vrp("198.51.100.0/24", 64501)], META);
        let mut w3 = Watcher::new(
            &cfg(),
            state.clone(),
            reqwest::Client::new(),
            Some(path.clone()),
        )
        .unwrap();
        w3.evaluate();
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.watch_not_found.load(Ordering::Relaxed), 1);

        // Corrupt state is ignored, not fatal.
        std::fs::write(&path, b"{garbage").unwrap();
        assert!(Watcher::new(&cfg(), state, reqwest::Client::new(), Some(path)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roa_expiry_warning() {
        let state = Arc::new(test_state());
        let metrics = state.metrics.clone();
        let mut w = Watcher::new(&cfg(), state.clone(), reqwest::Client::new(), None).unwrap();
        let now = 1_900_000_000;
        let mut d = VrpData::from_vrps([vrp("192.0.2.0/24", 64500), vrp("198.51.100.0/24", 64500)]);
        d.expires
            .insert(vrp("192.0.2.0/24", 64500), now + 3 * 86_400);
        d.expires
            .insert(vrp("198.51.100.0/24", 64500), now + 30 * 86_400);
        state.publish_data(d.clone(), META);
        w.evaluate_at(now);
        assert_eq!(metrics.watch_roa_expiring.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 1);
        w.evaluate_at(now);
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 1);
        // Renewed: resolved alert.
        d.expires
            .insert(vrp("192.0.2.0/24", 64500), now + 300 * 86_400);
        state.publish_data(d, META);
        w.evaluate_at(now);
        assert_eq!(metrics.watch_roa_expiring.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.alerts.load(Ordering::Relaxed), 2);
    }
}
