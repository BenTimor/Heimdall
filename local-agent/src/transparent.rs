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
/// In transparent interception mode (WinDivert/iptables), hairpin NAT causes ALL
/// connections to arrive from the machine's own NIC address, so this limit
/// effectively equals the global limit.
const MAX_CONNECTIONS_PER_IP: usize = MAX_CONCURRENT_CONNECTIONS;

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

    // Bind a secondary IPv6 listener so WinDivert hairpin-NAT works for both
    // address families. On Windows, IPV6_V6ONLY defaults to true, so a single
    // [::] socket does NOT accept IPv4 — we need both.
    let v6_addr = format!("[::]:{}", config.port);
    let v6_listener = TcpListener::bind(&v6_addr).await.ok();
    if v6_listener.is_some() {
        info!(addr = %v6_addr, "transparent IPv6 listener started");
    } else {
        debug!("IPv6 transparent listener not available (non-fatal)");
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let per_ip_counts: Arc<DashMap<IpAddr, usize>> = Arc::new(DashMap::new());

    // Helper future that never resolves (used when v6 listener is absent)
    async fn never() -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        std::future::pending().await
    }

    loop {
        // Accept from either the IPv4 or IPv6 listener, or shutdown
        let accept_result = tokio::select! {
            r = listener.accept() => r,
            r = async {
                match v6_listener.as_ref() {
                    Some(v6) => v6.accept().await,
                    None => never().await,
                }
            } => r,
            _ = shutdown.changed() => {
                info!("transparent listener shutting down");
                break;
            }
        };

        match accept_result {
            Ok((stream, peer)) => {
                debug!(peer = %peer, "transparent: accepted connection");
                if let Err(e) = stream.set_nodelay(true) {
                    warn!(peer = %peer, error = %e, "failed to set TCP_NODELAY on transparent connection");
                }
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
                    warn!(
                        "transparent listener at max concurrent connections ({})",
                        MAX_CONCURRENT_CONNECTIONS
                    );
                }
                tokio::spawn(async move {
                    if let Err(e) = handle_transparent(stream, mux, &df).await {
                        debug!(peer = %peer, error = %e, "transparent: connection failed");
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
    // TCP may deliver the ClientHello across multiple segments, so when we
    // get a partial read we retry until the full record arrives.
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let hostname = loop {
        let n = stream
            .peek(&mut buf)
            .await
            .context("peeking at ClientHello")?;

        if n == 0 {
            anyhow::bail!("connection closed before sending data");
        }

        match sni::extract_sni(&buf[..n]) {
            Ok(hostname) => break hostname,
            Err(sni::SniError::BufferTooShort { needed, .. }) if needed <= buf.len() => {
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "timeout waiting for complete ClientHello (have {} bytes, need {})",
                        n,
                        needed
                    );
                }
                // Rest of the ClientHello is still in-flight — brief yield then retry
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                continue;
            }
            Err(e) => return Err(anyhow::anyhow!("SNI extraction failed: {}", e)),
        }
    };

    if !is_valid_hostname(&hostname) {
        anyhow::bail!("invalid SNI hostname: {}", hostname);
    }

    debug!(hostname = %hostname, matched = domain_filter.matches(&hostname), "transparent: SNI extracted, checking domain filter");

    // Check if this domain needs tunneling
    if !domain_filter.matches(&hostname) {
        // Direct passthrough — no secrets for this domain
        debug!(hostname = %hostname, "transparent: direct passthrough (domain filter miss)");
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

    debug!(conn_id, hostname = %hostname, "transparent: routing through tunnel (domain filter hit)");
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
