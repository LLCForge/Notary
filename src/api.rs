//! HTTP API: validity queries (single and batch), status, VRP history, ASPA
//! path checks, Prometheus metrics and the embedded web UI. Read-only.

use std::fmt::Write as _;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use llcforge_beacon::ApiToken;
use serde::Deserialize;

use crate::aspa::{self, Direction};
use crate::history;
use crate::prefix::{parse_asn, Asn, Prefix};
use crate::state::AppState;
use crate::validator::validate;

/// Batch bodies: ~100 bytes per route at the default 10k-route limit.
const MAX_BODY: usize = 4 * 1024 * 1024;
const UI_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; \
    frame-ancestors 'none'";

#[derive(Clone)]
pub struct ApiOptions {
    pub token: Option<ApiToken>,
    pub ui: bool,
    pub max_batch: usize,
}

impl Default for ApiOptions {
    fn default() -> Self {
        ApiOptions {
            token: None,
            ui: true,
            max_batch: 10_000,
        }
    }
}

#[derive(Clone)]
struct Ctx {
    state: Arc<AppState>,
    max_batch: usize,
}

pub fn router(state: Arc<AppState>, opts: ApiOptions) -> Router {
    let ctx = Ctx {
        state,
        max_batch: opts.max_batch,
    };
    let mut v1 = Router::new()
        .route("/v1/validity", get(validity).post(validity_batch))
        .route("/v1/status", get(status))
        .route("/v1/history", get(history_query))
        .route("/v1/aspa", get(aspa_check));
    if let Some(token) = opts.token {
        v1 = v1.route_layer(axum::middleware::from_fn_with_state(
            token,
            llcforge_beacon::auth::require_bearer,
        ));
    }
    let mut app = v1.route("/metrics", get(metrics));
    if opts.ui {
        app = app
            .route("/", get(ui_index))
            .route("/ui/app.js", get(ui_js))
            .route("/ui/app.css", get(ui_css));
    }
    app.layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(ctx)
}

async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static("default-src 'none'"));
    resp
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn static_file(ctype: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(ctype)),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(UI_CSP),
            ),
        ],
        body,
    )
        .into_response()
}

async fn ui_index() -> Response {
    static_file("text/html; charset=utf-8", include_str!("ui/index.html"))
}

async fn ui_js() -> Response {
    static_file("text/javascript; charset=utf-8", include_str!("ui/app.js"))
}

async fn ui_css() -> Response {
    static_file("text/css; charset=utf-8", include_str!("ui/app.css"))
}

#[derive(Deserialize)]
struct ValidityQuery {
    prefix: Option<String>,
    asn: Option<String>,
}

/// Validates one route; `Err` is a client error message.
fn check_one(
    state: &AppState,
    stale: bool,
    prefix: &str,
    asn: Asn,
) -> Result<serde_json::Value, String> {
    if prefix.len() > 64 {
        return Err("prefix too long".into());
    }
    let prefix: Prefix = prefix.parse().map_err(|e| format!("prefix: {e}"))?;
    let v = validate(&state.table(), &prefix, asn.0);
    let mut body = serde_json::to_value(&v).unwrap_or_default();
    body["stale"] = serde_json::Value::Bool(stale);
    Ok(body)
}

async fn validity(
    State(ctx): State<Ctx>,
    q: Result<Query<ValidityQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let state = &ctx.state;
    state.metrics.api_requests.fetch_add(1, Ordering::Relaxed);
    let Ok(Query(q)) = q else {
        return error(StatusCode::BAD_REQUEST, "malformed query string");
    };
    let (Some(prefix), Some(asn)) = (q.prefix, q.asn) else {
        return error(
            StatusCode::BAD_REQUEST,
            "both prefix and asn parameters are required",
        );
    };
    if prefix.len() > 64 || asn.len() > 16 {
        return error(StatusCode::BAD_REQUEST, "parameter too long");
    }
    let asn = match parse_asn(&asn) {
        Ok(a) => Asn(a),
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("asn: {e}")),
    };
    let st = state.status();
    if !st.loaded {
        return error(StatusCode::SERVICE_UNAVAILABLE, "VRP set not loaded yet");
    }
    match check_one(state, st.stale, &prefix, asn) {
        Ok(b) => Json(b).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchBody {
    routes: Vec<BatchRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRoute {
    prefix: String,
    asn: Asn,
}

/// `POST /v1/validity` `{"routes":[{"prefix":"..","asn":64500}]}` ->
/// `{"results":[...]}` in request order; a bad entry yields
/// `{"prefix","asn","error"}` without failing the batch.
async fn validity_batch(
    State(ctx): State<Ctx>,
    body: Result<Json<BatchBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let state = &ctx.state;
    state.metrics.api_requests.fetch_add(1, Ordering::Relaxed);
    let body = match body {
        Ok(Json(b)) => b,
        Err(e) => return error(e.status(), format!("invalid body: {}", e.body_text())),
    };
    if body.routes.len() > ctx.max_batch {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("at most {} routes per batch", ctx.max_batch),
        );
    }
    let st = state.status();
    if !st.loaded {
        return error(StatusCode::SERVICE_UNAVAILABLE, "VRP set not loaded yet");
    }
    let results: Vec<serde_json::Value> = body
        .routes
        .iter()
        .map(|r| {
            check_one(state, st.stale, &r.prefix, r.asn).unwrap_or_else(|e| {
                serde_json::json!({
                    "prefix": r.prefix.chars().take(64).collect::<String>(),
                    "origin": r.asn.0,
                    "error": e,
                })
            })
        })
        .collect();
    Json(serde_json::json!({ "results": results, "stale": st.stale })).into_response()
}

async fn status(State(ctx): State<Ctx>) -> Response {
    ctx.state
        .metrics
        .api_requests
        .fetch_add(1, Ordering::Relaxed);
    Json(ctx.state.status()).into_response()
}

#[derive(Deserialize)]
struct HistoryParams {
    prefix: Option<String>,
    asn: Option<String>,
    since: Option<String>,
    limit: Option<usize>,
}

async fn history_query(
    State(ctx): State<Ctx>,
    q: Result<Query<HistoryParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let state = ctx.state.clone();
    state.metrics.api_requests.fetch_add(1, Ordering::Relaxed);
    let Ok(Query(q)) = q else {
        return error(StatusCode::BAD_REQUEST, "malformed query string");
    };
    let mut query = history::Query {
        limit: q.limit.unwrap_or(50).clamp(1, 1000),
        ..Default::default()
    };
    if let Some(p) = q.prefix.filter(|p| !p.is_empty()) {
        match p.get(..64.min(p.len())).unwrap_or("").parse() {
            Ok(p) => query.prefix = Some(p),
            Err(e) => return error(StatusCode::BAD_REQUEST, format!("prefix: {e}")),
        }
    }
    if let Some(a) = q.asn.filter(|a| !a.is_empty()) {
        match parse_asn(&a) {
            Ok(a) => query.asn = Some(a),
            Err(e) => return error(StatusCode::BAD_REQUEST, format!("asn: {e}")),
        }
    }
    if let Some(s) = q.since.filter(|s| !s.is_empty()) {
        match chrono::DateTime::parse_from_rfc3339(&s) {
            Ok(t) => query.since = Some(t.with_timezone(&chrono::Utc)),
            Err(_) => return error(StatusCode::BAD_REQUEST, "since: expected RFC 3339"),
        }
    }
    if state.history().is_none() {
        return error(StatusCode::NOT_FOUND, "VRP history is disabled");
    }
    let r = tokio::task::spawn_blocking(move || state.history().map(|h| h.query(&query))).await;
    match r {
        Ok(Some(Ok(events))) => Json(serde_json::json!({ "events": events })).into_response(),
        Ok(Some(Err(e))) => {
            tracing::error!(error = %e, "reading VRP history failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "reading history failed")
        }
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "reading history failed"),
    }
}

#[derive(Deserialize)]
struct AspaParams {
    path: Option<String>,
    direction: Option<String>,
}

async fn aspa_check(
    State(ctx): State<Ctx>,
    q: Result<Query<AspaParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let state = &ctx.state;
    state.metrics.api_requests.fetch_add(1, Ordering::Relaxed);
    let Ok(Query(q)) = q else {
        return error(StatusCode::BAD_REQUEST, "malformed query string");
    };
    let Some(path) = q.path.filter(|p| p.len() <= 4096) else {
        return error(
            StatusCode::BAD_REQUEST,
            "path parameter (<= 4096 bytes) is required",
        );
    };
    let direction = match q.direction.as_deref().unwrap_or("upstream") {
        "upstream" => Direction::Upstream,
        "downstream" => Direction::Downstream,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "direction must be upstream or downstream",
            )
        }
    };
    let path = match aspa::parse_path(&path) {
        Ok(p) => p,
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("path: {e}")),
    };
    let st = state.status();
    if !st.loaded {
        return error(StatusCode::SERVICE_UNAVAILABLE, "VRP set not loaded yet");
    }
    let r = aspa::verify(&state.table(), &path, direction);
    let mut body = serde_json::to_value(&r).unwrap_or_default();
    body["stale"] = serde_json::Value::Bool(st.stale);
    body["aspa_records"] = serde_json::Value::from(st.aspa_count);
    Json(body).into_response()
}

async fn metrics(State(ctx): State<Ctx>) -> Response {
    let state = &ctx.state;
    let st = state.status();
    let m = &state.metrics;
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, kind: &str, value: u64| {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}"
        );
    };
    let c = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    gauge(
        "notary_vrps_ipv4",
        "IPv4 VRPs in the active table.",
        "gauge",
        st.ipv4_vrps as u64,
    );
    gauge(
        "notary_vrps_ipv6",
        "IPv6 VRPs in the active table.",
        "gauge",
        st.ipv6_vrps as u64,
    );
    gauge(
        "notary_aspa_records",
        "ASPA records in the active table.",
        "gauge",
        st.aspa_count as u64,
    );
    gauge(
        "notary_vrp_serial",
        "RTR serial of the active table.",
        "gauge",
        u64::from(st.serial.unwrap_or(0)),
    );
    gauge(
        "notary_vrp_age_seconds",
        "Seconds since the last successful VRP update.",
        "gauge",
        st.age_secs.unwrap_or(0),
    );
    gauge(
        "notary_vrp_stale",
        "1 if VRP data is missing or older than the expire interval.",
        "gauge",
        u64::from(st.stale),
    );
    gauge(
        "notary_vrp_updates_total",
        "Applied VRP set updates.",
        "counter",
        c(&m.vrp_updates),
    );
    gauge(
        "notary_vrp_empty_rejected_total",
        "Empty VRP sets refused.",
        "counter",
        c(&m.vrp_empty_rejected),
    );
    gauge(
        "notary_vrp_source_errors_total",
        "Failed RTR sessions or JSON loads.",
        "counter",
        c(&m.source_errors),
    );
    gauge(
        "notary_slurm_filtered_vrps",
        "VRPs removed by SLURM filters in the active table.",
        "gauge",
        c(&m.slurm_filtered),
    );
    gauge(
        "notary_slurm_asserted_vrps",
        "VRPs added by SLURM assertions.",
        "gauge",
        c(&m.slurm_asserted),
    );
    gauge(
        "notary_ripestat_errors_total",
        "Failed RIPEstat prefix list fetches.",
        "counter",
        c(&m.ripestat_errors),
    );
    gauge(
        "notary_prefix_source_errors_total",
        "Failed prefix list fetches from any source (RIPEstat, Pathology, bgp.tools).",
        "counter",
        c(&m.prefix_source_errors),
    );
    gauge(
        "notary_watch_valid",
        "Watched routes currently Valid.",
        "gauge",
        c(&m.watch_valid),
    );
    gauge(
        "notary_watch_invalid",
        "Watched routes currently Invalid.",
        "gauge",
        c(&m.watch_invalid),
    );
    gauge(
        "notary_watch_not_found",
        "Watched routes currently NotFound.",
        "gauge",
        c(&m.watch_not_found),
    );
    gauge(
        "notary_watch_roa_expiring",
        "Watched Valid routes whose ROAs all expire within the warning window.",
        "gauge",
        c(&m.watch_roa_expiring),
    );
    gauge(
        "notary_alerts_total",
        "Alerts raised.",
        "counter",
        c(&m.alerts),
    );
    gauge(
        "notary_alerts_dropped_total",
        "Alerts the dispatcher did not accept.",
        "counter",
        c(&m.alerts_dropped),
    );
    gauge(
        "notary_history_errors_total",
        "Failed VRP history writes.",
        "counter",
        c(&m.history_errors),
    );
    gauge(
        "notary_api_requests_total",
        "Query API requests.",
        "counter",
        c(&m.api_requests),
    );
    state.alert_metrics().render_prometheus(&mut out);
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        out,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{test_state, UpdateMeta};
    use crate::vrp::{Vrp, VrpData};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn request(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> (u16, String, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        let code = buf[9..12].parse().unwrap();
        let (head, body) = buf.split_once("\r\n\r\n").unwrap_or((&buf, ""));
        (code, head.to_string(), body.to_string())
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
        let (c, _, b) = request(addr, "GET", path, "", "").await;
        (c, b)
    }

    async fn serve(state: Arc<AppState>, opts: ApiOptions) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let app = router(state, opts);
        tokio::spawn(async move { axum::serve(l, app).await });
        addr
    }

    const META: UpdateMeta = UpdateMeta {
        serial: Some(3),
        session_id: None,
        rtr_version: None,
        expire_secs: 7200,
    };

    #[tokio::test]
    async fn endpoints() {
        let state = Arc::new(test_state());
        let addr = serve(state.clone(), ApiOptions::default()).await;

        let (code, _) = get(addr, "/v1/validity?prefix=192.0.2.0/24&asn=AS64500").await;
        assert_eq!(code, 503);

        let vrp = Vrp::new("192.0.2.0/24".parse().unwrap(), 24, 64500).unwrap();
        let mut d = VrpData::from_vrps([vrp]);
        d.aspas.insert(64500, vec![64510]);
        state.publish_data(d, META);
        let (code, body) = get(addr, "/v1/validity?prefix=192.0.2.0/24&asn=AS64501").await;
        assert_eq!(code, 200);
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["state"], "invalid");
        assert_eq!(j["reason"], "wrong_origin");
        assert_eq!(j["stale"], false);

        assert_eq!(
            get(addr, "/v1/validity?prefix=192.0.2.1/24&asn=1").await.0,
            400
        );
        assert_eq!(get(addr, "/v1/validity?prefix=192.0.2.0/24").await.0, 400);
        assert_eq!(
            get(addr, "/v1/validity?prefix=192.0.2.0/24&asn=ASx")
                .await
                .0,
            400
        );

        // Batch.
        let (code, _, body) = request(
            addr,
            "POST",
            "/v1/validity",
            "Content-Type: application/json\r\n",
            r#"{"routes":[{"prefix":"192.0.2.0/24","asn":64500},{"prefix":"198.51.100.0/24","asn":"AS64500"},{"prefix":"bad","asn":1}]}"#,
        )
        .await;
        assert_eq!(code, 200, "{body}");
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        let r = j["results"].as_array().unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0]["state"], "valid");
        assert_eq!(r[1]["state"], "not_found");
        assert!(r[2]["error"].is_string());
        let (code, _, _) = request(
            addr,
            "POST",
            "/v1/validity",
            "Content-Type: application/json\r\n",
            "{",
        )
        .await;
        assert_eq!(code, 400);
        let too_many = format!(
            r#"{{"routes":[{}]}}"#,
            vec![r#"{"prefix":"192.0.2.0/24","asn":1}"#; 10_001].join(",")
        );
        let (code, _, _) = request(
            addr,
            "POST",
            "/v1/validity",
            "Content-Type: application/json\r\n",
            &too_many,
        )
        .await;
        assert_eq!(code, 413);

        // ASPA.
        let (code, body) = get(addr, "/v1/aspa?path=64510%2064500&direction=upstream").await;
        assert_eq!(code, 200, "{body}");
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["state"], "valid");
        assert_eq!(get(addr, "/v1/aspa?path=64510%20%7B1%7D").await.0, 400);
        assert_eq!(get(addr, "/v1/aspa?path=1&direction=sideways").await.0, 400);

        let (code, body) = get(addr, "/v1/status").await;
        assert_eq!(code, 200);
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["vrp_count"], 1);
        assert_eq!(j["serial"], 3);
        assert_eq!(j["aspa_count"], 1);

        // History disabled in this state.
        assert_eq!(get(addr, "/v1/history").await.0, 404);

        let (code, body) = get(addr, "/metrics").await;
        assert_eq!(code, 200);
        assert!(body.contains("notary_vrps_ipv4 1"));
        assert!(body.contains("notary_vrp_serial 3"));
        assert!(body.contains("notary_aspa_records 1"));

        // Web UI with its own CSP.
        let (code, head, body) = request(addr, "GET", "/", "", "").await;
        assert_eq!(code, 200);
        assert!(body.contains("<title>Notary</title>"));
        assert!(head.contains("script-src 'self'"));
        let (code, head, _) = request(addr, "GET", "/v1/status", "", "").await;
        assert_eq!(code, 200);
        assert!(head.contains("default-src 'none'"));
        assert_eq!(get(addr, "/ui/app.js").await.0, 200);
    }

    #[tokio::test]
    async fn bearer_token_and_history() {
        let dir = std::env::temp_dir().join(format!("notary-api-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = Arc::new(test_state().with_history(history::History::new(
            dir.join("h.jsonl"),
            1 << 20,
            100,
        )));
        let opts = ApiOptions {
            token: Some(ApiToken::new("0123456789abcdef-test").unwrap()),
            ui: false,
            max_batch: 10,
        };
        let addr = serve(state.clone(), opts).await;
        let v = |p: &str, a| Vrp::new(p.parse().unwrap(), 24, a).unwrap();
        state.publish([v("192.0.2.0/24", 64500)], META);
        state.publish(
            [v("192.0.2.0/24", 64500), v("198.51.100.0/24", 64501)],
            META,
        );

        assert_eq!(get(addr, "/v1/status").await.0, 401);
        assert_eq!(get(addr, "/metrics").await.0, 200);
        assert_eq!(get(addr, "/").await.0, 404);
        let auth = "Authorization: Bearer 0123456789abcdef-test\r\n";
        let (code, _, body) = request(addr, "GET", "/v1/history?asn=AS64501", auth, "").await;
        assert_eq!(code, 200, "{body}");
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["events"].as_array().unwrap().len(), 1);
        assert_eq!(j["events"][0]["added"][0]["prefix"], "198.51.100.0/24");
        let (code, _, _) = request(addr, "GET", "/v1/history?since=yesterday", auth, "").await;
        assert_eq!(code, 400);
        let (code, _, _) = request(
            addr,
            "GET",
            "/v1/status",
            "Authorization: Bearer wrong-token-000000\r\n",
            "",
        )
        .await;
        assert_eq!(code, 401);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
