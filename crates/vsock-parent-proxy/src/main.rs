//! PZDR Gateway parent-partition vsock proxy.
//!
//! Runs on the EC2 parent (NOT inside the enclave). Accepts HTTP traffic from
//! the ALB on 0.0.0.0:8090. For each request:
//!   1. Forward as length-prefixed framed JSON over vsock to the enclave
//!   2. Read framed JSON response
//!   3. Return as HTTP body
//!
//! No business logic runs here. The parent partition cannot see plaintext;
//! the enclave is the only component that decrypts client payloads.

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{error, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(name = "vsock-parent-proxy")]
struct Args {
    /// HTTP listen address (the ALB target).
    #[arg(long, env = "PROXY_ADDR", default_value = "0.0.0.0:8090")]
    listen: String,

    /// Enclave CID assigned in nitro-cli run-enclave.
    #[arg(long, env = "ENCLAVE_CID", default_value_t = 16)]
    enclave_cid: u32,

    /// Port the enclave's pzdr-enclave binary listens on inside the enclave.
    #[arg(long, env = "ENCLAVE_PORT", default_value_t = 5000)]
    enclave_port: u32,

    /// Per-request enclave timeout in milliseconds.
    #[arg(long, env = "ENCLAVE_TIMEOUT_MS", default_value_t = 30_000)]
    timeout_ms: u64,
}

#[derive(Clone)]
struct AppState {
    cid: u32,
    port: u32,
    timeout: std::time::Duration,
    metrics: Arc<Metrics>,
}

struct Metrics {
    requests: prometheus::IntCounter,
    errors: prometheus::IntCounter,
    latency_ms: prometheus::Histogram,
}
impl Metrics {
    fn new() -> Arc<Self> {
        let r = prometheus::default_registry();
        let requests = prometheus::IntCounter::new(
            "pzdr_proxy_requests_total",
            "total requests proxied to enclave",
        )
        .unwrap();
        let errors = prometheus::IntCounter::new(
            "pzdr_proxy_errors_total",
            "total errors talking to enclave",
        )
        .unwrap();
        let latency_ms = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "pzdr_proxy_enclave_latency_ms",
                "enclave round-trip latency",
            )
            .buckets(vec![
                1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
            ]),
        )
        .unwrap();
        r.register(Box::new(requests.clone())).ok();
        r.register(Box::new(errors.clone())).ok();
        r.register(Box::new(latency_ms.clone())).ok();
        Arc::new(Metrics {
            requests,
            errors,
            latency_ms,
        })
    }
}

/// Framed JSON envelope on the vsock wire.
/// `[ u32 length BE | utf-8 JSON ]`
#[derive(Serialize, Deserialize, Debug)]
struct VsockEnvelope {
    method: String,
    path: String,
    headers: serde_json::Map<String, serde_json::Value>,
    body_b64: String, // base64 — vsock framing is binary-safe but JSON is not
}

#[derive(Serialize, Deserialize, Debug)]
struct VsockResponse {
    status: u16,
    headers: serde_json::Map<String, serde_json::Value>,
    body_b64: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,vsock_parent_proxy=debug".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    info!(?args, "vsock-parent-proxy starting");

    let state = AppState {
        cid: args.enclave_cid,
        port: args.enclave_port,
        timeout: std::time::Duration::from_millis(args.timeout_ms),
        metrics: Metrics::new(),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(metrics_handler))
        .route("/v1/attestation", get(forward_attestation))
        .route("/v1/gateway/inference", post(forward_inference))
        .route("/v1/ledger/root", get(forward_ledger_root))
        .route("/v1/ledger/proof/:idx", get(forward_path))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    info!(addr=%args.listen, "listening");
    notify_systemd_ready(&args.listen);
    spawn_systemd_watchdog();
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

fn notify_systemd_ready(addr: &str) {
    if let Err(e) = sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status(&format!("listening on {addr}")),
    ]) {
        warn!(?e, "systemd ready notification failed");
    }
}

fn spawn_systemd_watchdog() {
    let Some(period) = sd_notify::watchdog_enabled() else {
        return;
    };
    let mut tick = period / 2;
    if tick < std::time::Duration::from_secs(1) {
        tick = std::time::Duration::from_secs(1);
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        loop {
            interval.tick().await;
            if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]) {
                warn!(?e, "systemd watchdog notification failed");
            }
        }
    });
}

async fn metrics_handler() -> impl IntoResponse {
    use prometheus::Encoder;
    let metrics = prometheus::default_registry().gather();
    let mut buf = Vec::new();
    let _ = prometheus::TextEncoder::new().encode(&metrics, &mut buf);
    (StatusCode::OK, String::from_utf8_lossy(&buf).into_owned())
}

async fn forward_attestation(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    do_forward(state, "GET".into(), "/v1/attestation".into(), headers, body).await
}

async fn forward_inference(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    do_forward(
        state,
        "POST".into(),
        "/v1/gateway/inference".into(),
        headers,
        body,
    )
    .await
}

async fn forward_ledger_root(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    do_forward(state, "GET".into(), "/v1/ledger/root".into(), headers, body).await
}

async fn forward_path(
    State(state): State<AppState>,
    Path(idx): Path<u64>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    do_forward(
        state,
        "GET".into(),
        format!("/v1/ledger/proof/{idx}"),
        headers,
        body,
    )
    .await
}

async fn do_forward(
    state: AppState,
    method: String,
    path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    state.metrics.requests.inc();
    let started = std::time::Instant::now();

    // Build envelope
    let mut hdr_map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        if let Ok(s) = value.to_str() {
            hdr_map.insert(
                name.as_str().to_string(),
                serde_json::Value::String(s.to_string()),
            );
        }
    }
    use base64::Engine as _;
    let envelope = VsockEnvelope {
        method,
        path,
        headers: hdr_map,
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    let req_bytes = serde_json::to_vec(&envelope)?;

    // vsock round trip with timeout
    let cid = state.cid;
    let port = state.port;
    let timeout = state.timeout;

    let result = tokio::time::timeout(timeout, async move {
        let mut stream = VsockStream::connect(VsockAddr::new(cid, port))
            .await
            .with_context(|| format!("vsock connect cid={cid} port={port}"))?;
        write_framed(&mut stream, &req_bytes).await?;
        let resp_bytes = read_framed(&mut stream).await?;
        let resp: VsockResponse =
            serde_json::from_slice(&resp_bytes).context("decode VsockResponse")?;
        Ok::<_, anyhow::Error>(resp)
    })
    .await;

    let elapsed_ms = started.elapsed().as_millis() as f64;
    state.metrics.latency_ms.observe(elapsed_ms);

    let resp = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            state.metrics.errors.inc();
            error!(?e, "vsock round trip failed");
            return Err(AppError::Upstream(e.to_string()));
        }
        Err(_) => {
            state.metrics.errors.inc();
            warn!(?timeout, "enclave timeout");
            return Err(AppError::Timeout);
        }
    };

    // Reconstruct HTTP response
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(&resp.body_b64)
        .unwrap_or_default();
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in resp.headers.iter() {
        if let Some(s) = v.as_str() {
            builder = builder.header(k, s);
        }
    }
    Ok(builder.body(body_bytes.into()).unwrap())
}

async fn write_framed(stream: &mut VsockStream, bytes: &[u8]) -> Result<()> {
    let len = (bytes.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
async fn read_framed(stream: &mut VsockStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        anyhow::bail!("vsock frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[derive(Debug)]
enum AppError {
    Upstream(String),
    Timeout,
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AppError::Upstream(s) => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({"error": "upstream", "detail": s}),
            ),
            AppError::Timeout => (
                StatusCode::GATEWAY_TIMEOUT,
                serde_json::json!({"error": "enclave_timeout"}),
            ),
        };
        (status, axum::Json(body)).into_response()
    }
}
impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Upstream(e.to_string())
    }
}
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Upstream(e.to_string())
    }
}
