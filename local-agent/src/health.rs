use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tracing::info;

use crate::config::HealthConfig;
use crate::tunnel::multiplexer::Multiplexer;

/// Shared state for the health endpoint.
pub struct HealthState {
    pub multiplexer: Arc<Multiplexer>,
    pub started_at: Instant,
}

pub async fn run_health_server(
    config: &HealthConfig,
    state: Arc<HealthState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let app = Router::new()
        .route("/health", get(health_handler))
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("binding health server on {}", addr))?;
    info!(addr = %addr, "health endpoint listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .context("health server error")?;

    Ok(())
}

async fn health_handler(State(state): State<Arc<HealthState>>) -> Json<Value> {
    let status = state.multiplexer.status_async().await;
    let uptime_secs = state.started_at.elapsed().as_secs();
    let last_hb_ago_secs = status.last_heartbeat.elapsed().as_secs();

    Json(json!({
        "status": "ok",
        "tunnel_uptime_secs": uptime_secs,
        "active_connections": status.active_connections,
        "last_heartbeat_secs_ago": last_hb_ago_secs,
    }))
}
