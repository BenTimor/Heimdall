use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::TransparentConfig;
use crate::domain_filter::DomainFilter;
use crate::sni;
use crate::tunnel::multiplexer::Multiplexer;

/// Maximum number of concurrent transparent connections.
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Maximum number of concurrent connections from a single IP.
const MAX_CONNECTIONS_PER_IP: usize = 100;

/// Run the transparent TCP listener.
///
/// Accepts raw TCP connections, extracts the target hostname from the TLS
/// ClientHello SNI extension, and routes through the tunnel multiplexer.
/// Unlike the CONNECT proxy, no HTTP parsing is needed — the original TLS
/// bytes are forwarded intact.
pub async fn run_transparent_listener(
    config: &TransparentConfig,
    multiplexer: Arc<Multiplexer>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    domain_filter: Arc<DomainFilter>,
) -> Result<()> {
    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("binding transparent listener on {}", addr))?;
    info!(addr = %addr, "transparent listener started");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let per_ip_counts: Arc<DashMap<IpAddr, usize>> = Arc::new(DashMap::new());

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        debug!(peer = %peer, "accepted transparent connection");
                        let ip = peer.ip();
                        {
                            let mut count = per_ip_counts.entry(ip).or_insert(0);
                            if *count >= MAX_CONNECTIONS_PER_IP {
                                warn!(ip = %ip, "per-IP connection limit reached ({})", MAX_CONNECTIONS_PER_IP);
                                continue;
                            }
                            *count += 1;
                        }
                        let mux = multiplexer.clone();
                        let per_ip = per_ip_counts.clone();
                        let df = domain_filter.clone();
                        let sem = semaphore.clone();
                        let permit = match sem.acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!("connection semaphore closed unexpectedly");
                                break;
                            }
                        };
                        if semaphore.available_permits() == 0 {
                            warn!("transparent listener at max concurrent connections ({})", MAX_CONCURRENT_CONNECTIONS);
                        }
                        tokio::spawn(async move {
                            if let Err(e) = handle_transparent(stream, mux, &df).await {
                                debug!(peer = %peer, error = %e, "transparent connection failed");
                            }
                            if let Some(mut count) = per_ip.get_mut(&ip) {
                                *count = count.saturating_sub(1);
                            }
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept error on transparent listener");
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("transparent listener shutting down");
                break;
            }
        }
    }
    Ok(())
}

/// Handle a single transparent connection.
///
/// Peeks at the initial bytes to extract SNI, then hands the full stream
/// (with ClientHello still in the buffer) to the multiplexer.
async fn handle_transparent(
    stream: tokio::net::TcpStream,
    mux: Arc<Multiplexer>,
    domain_filter: &DomainFilter,
) -> Result<()> {
    // Peek at the ClientHello without consuming it from the kernel buffer.
    let mut buf = [0u8; 4096];
    let n = stream
        .peek(&mut buf)
        .await
        .context("peeking at ClientHello")?;

    if n == 0 {
        anyhow::bail!("connection closed before sending data");
    }

    let hostname = sni::extract_sni(&buf[..n])
        .map_err(|e| anyhow::anyhow!("SNI extraction failed: {}", e))?;

    if !is_valid_hostname(&hostname) {
        anyhow::bail!("invalid SNI hostname: {}", hostname);
    }

    info!(hostname = %hostname, matched = domain_filter.matches(&hostname), "transparent: SNI extracted, checking domain filter");

    // Check if this domain needs tunneling
    if !domain_filter.matches(&hostname) {
        // Direct passthrough — no secrets for this domain
        info!(hostname = %hostname, "transparent: direct passthrough (domain filter miss)");
        let mut target = TcpStream::connect(format!("{}:{}", hostname, 443))
            .await
            .context("connecting to target for direct passthrough")?;

        let mut stream = stream;
        let _ = copy_bidirectional(&mut stream, &mut target).await;
        return Ok(());
    }

    let conn_id = mux
        .new_connection(stream, &hostname, 443)
        .await
        .context("opening tunnel connection for transparent stream")?;

    info!(conn_id, hostname = %hostname, "transparent: routing through tunnel (domain filter hit)");
    Ok(())
}

/// Validate that a hostname conforms to DNS rules.
///
/// Checks: total length <= 253 characters, each label <= 63 characters,
/// labels contain only `[a-zA-Z0-9-]`, labels don't start or end with `-`.
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    true
}
