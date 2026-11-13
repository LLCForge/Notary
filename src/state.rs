//! Shared daemon state: the current VRP table (swapped atomically), source
//! status, SLURM, change history, readiness and counters.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use llcforge_beacon::{Alert, AlertHandle, Readiness, Severity};
use serde::Serialize;
use tokio::sync::watch;

use crate::history::History;
use crate::slurm::Slurm;
#[cfg(test)]
use crate::vrp::Vrp;
use crate::vrp::{VrpData, VrpTable};

pub const TOOL: &str = "notary";
/// Readiness check name: VRP data loaded and fresh.
pub const READY_VRP: &str = "vrp_data";

/// Builds a Notary alert.
pub fn alert(kind: &str, severity: Severity, title: impl Into<String>) -> Alert {
    Alert::new(TOOL, kind, severity, title)
}

#[derive(Default)]
pub struct Metrics {
    pub vrp_updates: AtomicU64,
    pub vrp_empty_rejected: AtomicU64,
    pub source_errors: AtomicU64,
    pub alerts: AtomicU64,
    pub alerts_dropped: AtomicU64,
    pub api_requests: AtomicU64,
    pub ripestat_errors: AtomicU64,
    pub prefix_source_errors: AtomicU64,
    pub watch_valid: AtomicU64,
    pub watch_invalid: AtomicU64,
    pub watch_not_found: AtomicU64,
    pub watch_roa_expiring: AtomicU64,
    pub slurm_filtered: AtomicU64,
    pub slurm_asserted: AtomicU64,
    pub history_errors: AtomicU64,
}

/// Metadata attached to a published VRP set.
#[derive(Debug, Clone, Copy)]
pub struct UpdateMeta {
    pub serial: Option<u32>,
    pub session_id: Option<u16>,
    pub rtr_version: Option<u8>,
    /// Seconds after the last successful update at which data counts as stale.
    pub expire_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub source: String,
    pub loaded: bool,
    pub vrp_count: usize,
    pub ipv4_vrps: usize,
    pub ipv6_vrps: usize,
    pub aspa_count: usize,
    pub serial: Option<u32>,
    pub session_id: Option<u16>,
    pub rtr_version: Option<u8>,
    pub last_update_unix: Option<u64>,
    pub age_secs: Option<u64>,
    pub expire_secs: u64,
    pub stale: bool,
    pub slurm: bool,
    pub last_error: Option<String>,
}

struct Inner {
    meta: UpdateMeta,
    last_update: Option<Instant>,
    last_update_unix: Option<u64>,
    last_error: Option<String>,
    /// Last payload set as received, before SLURM (re-applied on reload).
    raw: Option<Arc<VrpData>>,
    slurm: Option<Arc<Slurm>>,
}

pub struct AppState {
    source: String,
    table: RwLock<Arc<VrpTable>>,
    inner: Mutex<Inner>,
    generation: watch::Sender<u64>,
    stale_alerted: AtomicBool,
    alerts: RwLock<AlertHandle>,
    history: Option<History>,
    pub readiness: Readiness,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new(
        source: String,
        expire_secs: u64,
        alerts: AlertHandle,
        metrics: Arc<Metrics>,
    ) -> Self {
        let readiness = Readiness::new();
        readiness.register(READY_VRP);
        AppState {
            source,
            table: RwLock::new(Arc::new(VrpTable::default())),
            inner: Mutex::new(Inner {
                meta: UpdateMeta {
                    serial: None,
                    session_id: None,
                    rtr_version: None,
                    expire_secs,
                },
                last_update: None,
                last_update_unix: None,
                last_error: None,
                raw: None,
                slurm: None,
            }),
            generation: watch::channel(0).0,
            stale_alerted: AtomicBool::new(false),
            alerts: RwLock::new(alerts),
            history: None,
            readiness,
            metrics,
        }
    }

    pub fn with_history(mut self, h: History) -> Self {
        self.history = Some(h);
        self
    }

    pub fn with_slurm(self, s: Option<Slurm>) -> Self {
        self.lock().slurm = s.map(Arc::new);
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn history(&self) -> Option<&History> {
        self.history.as_ref()
    }

    /// Raises an alert through the current dispatcher (never blocks).
    pub fn alert(&self, a: Alert) {
        tracing::warn!(kind = %a.kind, resource = ?a.resource, "ALERT: {}", a.title);
        self.metrics.alerts.fetch_add(1, Ordering::Relaxed);
        let h = self
            .alerts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !h.send(a) {
            self.metrics.alerts_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Delivery metrics of the current dispatcher (`llcforge_beacon_*`).
    pub fn alert_metrics(&self) -> Arc<llcforge_beacon::Metrics> {
        self.alerts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .metrics()
    }

    /// Swaps the alert dispatcher handle (configuration reload).
    pub fn set_alerts(&self, h: AlertHandle) {
        *self.alerts.write().unwrap_or_else(PoisonError::into_inner) = h;
    }

    pub fn table(&self) -> Arc<VrpTable> {
        self.table
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    #[cfg(test)]
    pub fn publish<I: IntoIterator<Item = Vrp>>(&self, vrps: I, meta: UpdateMeta) -> bool {
        self.publish_data(VrpData::from_vrps(vrps), meta)
    }

    /// Replaces SLURM rules and re-applies them to the last received set.
    pub fn set_slurm(&self, s: Option<Slurm>) {
        let (raw, meta) = {
            let mut inner = self.lock();
            inner.slurm = s.map(Arc::new);
            (inner.raw.clone(), inner.meta)
        };
        if let Some(raw) = raw {
            self.publish_data((*raw).clone(), meta);
        }
    }

    /// Publishes a new payload set after applying SLURM. An empty VRP set is
    /// refused (it would turn every route NotFound) and raises an alert
    /// instead. Returns whether applied.
    pub fn publish_data(&self, raw: VrpData, meta: UpdateMeta) -> bool {
        let slurm = {
            let mut inner = self.lock();
            inner.raw = Some(Arc::new(raw.clone()));
            inner.slurm.clone()
        };
        let mut data = raw;
        if let Some(s) = &slurm {
            let (f, a) = s.apply(&mut data);
            self.metrics
                .slurm_filtered
                .store(f as u64, Ordering::Relaxed);
            self.metrics
                .slurm_asserted
                .store(a as u64, Ordering::Relaxed);
        }
        if data.vrps.is_empty() {
            self.metrics
                .vrp_empty_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.alert(
                alert(
                    "vrp_empty_rejected",
                    Severity::Critical,
                    format!(
                        "VRP source {} delivered an empty set; keeping the previous one",
                        self.source
                    ),
                )
                .resource(self.source.clone())
                .field("serial", format!("{:?}", meta.serial)),
            );
            return false;
        }
        let table = VrpTable::build(data);
        let count = table.len();
        let old = self.table();
        if let Some(h) = &self.history {
            let prev = (!old.is_empty()).then(|| (old.vrps(), &old.data().aspas));
            if let Some(ev) = h.event(prev, table.vrps(), &table.data().aspas, meta.serial) {
                if let Err(e) = h.append(&ev) {
                    self.metrics.history_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(error = %e, path = %h.path().display(), "writing VRP history failed");
                }
            }
        }
        drop(old);
        *self.table.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(table);
        self.mark_fresh(meta);
        self.metrics.vrp_updates.fetch_add(1, Ordering::Relaxed);
        tracing::info!(vrps = count, serial = ?meta.serial, "VRP set updated");
        self.generation.send_modify(|g| *g += 1);
        true
    }

    /// Records a successful refresh that did not change the VRP set.
    pub fn mark_fresh(&self, meta: UpdateMeta) {
        {
            let mut inner = self.lock();
            inner.meta = meta;
            inner.last_update = Some(Instant::now());
            inner.last_update_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
            inner.last_error = None;
        }
        self.readiness.set(READY_VRP, true);
        if self.stale_alerted.swap(false, Ordering::Relaxed) {
            self.alert(
                alert(
                    "vrp_stale",
                    Severity::Warning,
                    format!("VRP data from {} is fresh again", self.source),
                )
                .resource(self.source.clone())
                .resolved(true),
            );
        }
    }

    pub fn record_error(&self, err: &anyhow::Error) {
        self.metrics.source_errors.fetch_add(1, Ordering::Relaxed);
        self.lock().last_error = Some(format!("{err:#}"));
    }

    pub fn status(&self) -> Status {
        let table = self.table();
        let inner = self.lock();
        let age = inner.last_update.map(|t| t.elapsed());
        Status {
            source: self.source.clone(),
            loaded: inner.last_update.is_some(),
            vrp_count: table.len(),
            ipv4_vrps: table.v4_count(),
            ipv6_vrps: table.v6_count(),
            aspa_count: table.aspa_count(),
            serial: inner.meta.serial,
            session_id: inner.meta.session_id,
            rtr_version: inner.meta.rtr_version,
            last_update_unix: inner.last_update_unix,
            age_secs: age.map(|a| a.as_secs()),
            expire_secs: inner.meta.expire_secs,
            stale: age.is_none_or(|a| a > Duration::from_secs(inner.meta.expire_secs)),
            slurm: inner.slurm.is_some(),
            last_error: inner.last_error.clone(),
        }
    }

    /// Raises a one-shot alert when data that was once loaded goes stale and
    /// keeps the readiness check in sync.
    pub fn check_staleness(&self) {
        let s = self.status();
        self.readiness.set_detail(
            READY_VRP,
            s.loaded && !s.stale,
            s.last_error
                .clone()
                .or_else(|| (!s.loaded).then(|| "not loaded yet".into())),
        );
        if s.loaded && s.stale && !self.stale_alerted.swap(true, Ordering::Relaxed) {
            self.alert(
                alert(
                    "vrp_stale",
                    Severity::Warning,
                    format!(
                        "VRP data from {} is stale: last update {}s ago (expire {}s)",
                        s.source,
                        s.age_secs.unwrap_or(0),
                        s.expire_secs
                    ),
                )
                .resource(s.source.clone())
                .field("last_error", s.last_error.as_deref().unwrap_or("none")),
            );
        }
    }
}

#[cfg(test)]
pub fn test_state() -> AppState {
    let m = Arc::new(Metrics::default());
    AppState::new("test".into(), 7200, AlertHandle::disabled(TOOL), m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const META: UpdateMeta = UpdateMeta {
        serial: Some(1),
        session_id: Some(1),
        rtr_version: Some(1),
        expire_secs: 7200,
    };

    #[test]
    fn empty_set_is_refused() {
        let s = test_state();
        let v = Vrp::new("192.0.2.0/24".parse().unwrap(), 24, 64500).unwrap();
        assert!(s.publish([v], META));
        assert!(!s.publish([], META));
        assert_eq!(s.table().len(), 1);
        assert_eq!(s.metrics.vrp_empty_rejected.load(Ordering::Relaxed), 1);
        assert!(!s.status().stale);
        assert!(s.readiness.is_ready());
    }

    #[test]
    fn stale_before_first_load() {
        let s = test_state();
        let st = s.status();
        assert!(!st.loaded);
        assert!(st.stale);
        s.check_staleness();
        assert!(!s.readiness.is_ready());
    }

    #[test]
    fn slurm_reapplied_on_change() {
        let s = test_state();
        let v = |p: &str, a| Vrp::new(p.parse().unwrap(), 24, a).unwrap();
        s.publish(
            [v("192.0.2.0/24", 64500), v("198.51.100.0/24", 64501)],
            META,
        );
        let slurm = crate::slurm::Slurm::parse(
            br#"{"slurmVersion":1,
                "validationOutputFilters":{"prefixFilters":[{"asn":64500}],"bgpsecFilters":[]},
                "locallyAddedAssertions":{"prefixAssertions":[{"asn":64502,"prefix":"203.0.113.0/24"}],"bgpsecAssertions":[]}}"#,
        )
        .unwrap();
        s.set_slurm(Some(slurm));
        assert_eq!(
            s.table().vrps(),
            &[v("198.51.100.0/24", 64501), v("203.0.113.0/24", 64502)]
        );
        assert!(s.status().slurm);
        s.set_slurm(None);
        assert_eq!(s.table().len(), 2);
        assert!(s.table().vrps().contains(&v("192.0.2.0/24", 64500)));
    }
}
