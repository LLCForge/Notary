//! `notary run` / `notary service run`: keeps VRPs fresh, watches routes,
//! alerts, serves the API, and reloads its configuration on SIGHUP, file
//! change or `POST /v1/reload`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use llcforge_beacon::{
    health_router, reload_router, silences_router, ApiToken, Dispatcher, DispatcherOptions,
    ReloadSignal, ServiceSpec, Shutdown, SilenceStore,
};
use tokio::task::JoinHandle;

use crate::api::{self, ApiOptions};
use crate::config::{Config, VrpSource};
use crate::history::History;
use crate::slurm::Slurm;
use crate::state::{AppState, Metrics, UpdateMeta, TOOL};
use crate::{http, rtr, vrp, watch};

pub const SPEC: ServiceSpec = ServiceSpec {
    bin: TOOL,
    display_name: "Notary",
    description: "RPKI Route Origin Validation checker with RTR client, watch daemon and query API",
};

const GRACE: Duration = Duration::from_secs(5);

/// Entry point for `run` and the Windows service; builds its own runtime.
pub fn daemon(config: PathBuf, shutdown: Shutdown) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting Tokio runtime")?
        .block_on(run(config, shutdown))
}

fn start_dispatcher(
    cfg: &Config,
    data_dir: &Path,
    silences: &Arc<SilenceStore>,
    client: &reqwest::Client,
) -> anyhow::Result<Dispatcher> {
    Dispatcher::start(
        &cfg.alerts,
        DispatcherOptions {
            tool: TOOL.into(),
            data_dir: Some(data_dir.to_path_buf()),
            silences: Some(silences.clone()),
            http: Some(client.clone()),
        },
    )
    .context("starting alert dispatcher")
}

fn start_watcher(
    cfg: &Config,
    state: &Arc<AppState>,
    client: &reqwest::Client,
    data_dir: &Path,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    let w = watch::Watcher::new(
        cfg,
        state.clone(),
        client.clone(),
        Some(data_dir.join("watch-state.json")),
    )?;
    Ok((!w.is_empty()).then(|| tokio::spawn(w.run())))
}

async fn run(config: PathBuf, mut shutdown: Shutdown) -> anyhow::Result<()> {
    let cfg = Config::load(&config)?;
    let data_dir = cfg.data_dir();
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data directory {}", data_dir.display()))?;
    let client = http::client()?;
    let silences = Arc::new(SilenceStore::open(cfg.silences.path_or(&data_dir))?);
    let mut dispatcher = start_dispatcher(&cfg, &data_dir, &silences, &client)?;

    let source = cfg.source()?;
    let (label, expire) = match &source {
        VrpSource::Rtr(t) => (t.to_string(), u64::from(rtr::pdu::Timing::DEFAULT.expire)),
        VrpSource::Json(j) => (j.clone(), cfg.vrp.json_expire_secs),
    };
    let mut state = AppState::new(
        label,
        expire,
        dispatcher.handle(),
        Arc::new(Metrics::default()),
    )
    .with_slurm(Slurm::load(&cfg.vrp.slurm)?);
    if cfg.history.enabled {
        state = state.with_history(History::new(
            data_dir.join("vrp-history.jsonl"),
            cfg.history.max_bytes,
            cfg.history.max_listed,
        ));
    }
    let state = Arc::new(state);

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    match source {
        VrpSource::Rtr(target) => {
            tasks.push(tokio::spawn(rtr::client::run(*target, state.clone())))
        }
        VrpSource::Json(src) => {
            let refresh = Duration::from_secs(cfg.vrp.json_refresh_secs);
            let expire_secs = cfg.vrp.json_expire_secs;
            let (st, client) = (state.clone(), client.clone());
            tasks.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(refresh);
                loop {
                    tick.tick().await;
                    match vrp::load_json_data(&src, &client).await {
                        Ok(d) => {
                            st.publish_data(
                                d,
                                UpdateMeta {
                                    serial: None,
                                    session_id: None,
                                    rtr_version: None,
                                    expire_secs,
                                },
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %format!("{e:#}"), "loading VRPs from {src} failed");
                            st.record_error(&e);
                        }
                    }
                }
            }));
        }
    }
    {
        let st = state.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                st.check_staleness();
            }
        }));
    }
    let mut watcher = start_watcher(&cfg, &state, &client, &data_dir)?;

    let mut reload = ReloadSignal::standard(Some(config.clone()))?;
    let mut admin = health_router(state.readiness.clone());
    if let Some(var) = &cfg.silences.api_token_env {
        admin = admin.merge(silences_router(silences.clone(), ApiToken::from_env(var)?));
    }
    if let Some(var) = &cfg.health.admin_token_env {
        admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
    }
    let api_token = cfg
        .api
        .token_env
        .as_deref()
        .map(ApiToken::from_env)
        .transpose()?;
    let mut servers = Vec::new();
    if cfg.api.enabled {
        if !cfg.api.listen.ip().is_loopback() {
            tracing::warn!(listen = %cfg.api.listen, "query API is bound to a non-loopback address");
        }
        let app = api::router(
            state.clone(),
            ApiOptions {
                token: api_token,
                ui: cfg.api.ui,
                max_batch: cfg.api.max_batch,
            },
        )
        .merge(admin.clone());
        let listener = tokio::net::TcpListener::bind(cfg.api.listen)
            .await
            .with_context(|| format!("binding API listener {}", cfg.api.listen))?;
        tracing::info!(listen = %cfg.api.listen, "query API listening");
        let mut sd = shutdown.clone();
        servers.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async move { sd.wait().await })
                .await
            {
                tracing::error!(error = %e, "API server failed");
            }
        }));
    }
    if let Some(addr) = cfg
        .health
        .listen
        .filter(|a| !cfg.api.enabled || *a != cfg.api.listen)
    {
        let mut sd = shutdown.clone();
        servers.push(tokio::spawn(async move {
            if let Err(e) =
                llcforge_beacon::serve(addr, admin, async move { sd.wait().await }).await
            {
                tracing::error!(error = %e, "health listener failed");
            }
        }));
    }

    let (old_source, old_listen) = (cfg.source_spec(), cfg.api.listen);
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            Some(reason) = reload.recv() => {
                tracing::info!(?reason, "reloading configuration");
                let new = match Config::load(&config).and_then(|c| Slurm::load(&c.vrp.slurm).map(|s| (c, s))) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %format!("{e:#}"), "invalid configuration; keeping the old one");
                        continue;
                    }
                };
                let (new, slurm) = new;
                if new.source_spec() != old_source || new.api.listen != old_listen {
                    tracing::warn!("VRP source / API listener changes need a restart; other settings applied");
                }
                match start_dispatcher(&new, &data_dir, &silences, &client) {
                    Ok(d) => {
                        state.set_alerts(d.handle());
                        std::mem::replace(&mut dispatcher, d).shutdown(GRACE).await;
                    }
                    Err(e) => tracing::error!(error = %format!("{e:#}"), "alert configuration rejected; keeping the old one"),
                }
                state.set_slurm(slurm);
                match start_watcher(&new, &state, &client, &data_dir) {
                    Ok(w) => {
                        if let Some(old) = std::mem::replace(&mut watcher, w) {
                            old.abort();
                        }
                    }
                    Err(e) => tracing::error!(error = %format!("{e:#}"), "watch configuration rejected; keeping the old one"),
                }
                tracing::info!("configuration reloaded");
            }
        }
    }
    tracing::info!("shutting down");
    for t in tasks.into_iter().chain(watcher) {
        t.abort();
    }
    for s in servers {
        let _ = tokio::time::timeout(GRACE, s).await;
    }
    dispatcher.shutdown(GRACE).await;
    Ok(())
}
