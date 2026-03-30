use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use dashmap::DashMap;
use subtle::ConstantTimeEq;
use tokio::io::{copy_bidirectional, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::LocalProxyConfig;
use crate::domain_filter::DomainFilter;
use crate::tunnel::multiplexer::Multiplexer;

/// Maximum number of concurrent proxy connections.
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Maximum number of concurrent connections from a single IP.
const MAX_CONNECTIONS_PER_IP: usize = 100;

/// Run the local HTTP CONNECT proxy.
/// Users point HTTPS_PROXY=http://127.0.0.1:19080 at this.
pub async fn run_local_proxy(
    config: &LocalProxyConfig,
    multiplexer: Arc<Multiplexer>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    domain_filter: Arc<DomainFilter>,
) -> Result<()> {
    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("binding local proxy on {}", addr))?;
    info!(addr = %addr, "local CONNECT proxy listening");

    let auth_token = config.auth_token.clone();
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let per_ip_counts: Arc<DashMap<IpAddr, usize>> = Arc::new(DashMap::new());

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        debug!(peer = %peer, "accepted local connection");
                        if let Err(e) = stream.set_nodelay(true) {
                            warn!(peer = %peer, error = %e, "failed to set TCP_NODELAY on local proxy connection");
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
                        let auth = auth_token.clone();
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
                            warn!("local proxy at max concurrent connections ({})", MAX_CONCURRENT_CONNECTIONS);
                        }
                        tokio::spawn(async move {
                            if let Err(e) = handle_connect(stream, mux, auth.as_deref(), &df).await {
                                warn!(peer = %peer, error = %e, "CONNECT handling failed");
                            }
                            if let Some(mut count) = per_ip.get_mut(&ip) {
                                *count = count.saturating_sub(1);
                            }
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept error on local proxy");
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("local proxy shutting down");
                break;
            }
        }
    }
    Ok(())
}

/// Handle one CONNECT request.
async fn handle_connect(
    stream: TcpStream,
    mux: Arc<Multiplexer>,
    auth_token: Option<&str>,
    domain_filter: &DomainFilter,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read the request line: "CONNECT host:port HTTP/1.1\r\n"
    let mut request_line = String::new();
    buf_reader
        .read_line(&mut request_line)
        .await
        .context("reading CONNECT request line")?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        anyhow::bail!("invalid CONNECT request: {}", request_line.trim());
    }

    let target = parts[1];
    let (host, port) = parse_host_port(target)?;

    // Consume remaining headers until empty line, collecting them for auth check.
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        headers.push(line);
    }

    // Check Proxy-Authorization if auth_token is configured.
    if let Some(expected_token) = auth_token {
        let proxy_auth = headers.iter().find_map(|h| {
            let trimmed = h.trim();
            if trimmed
                .to_ascii_lowercase()
                .starts_with("proxy-authorization:")
            {
                Some(trimmed["proxy-authorization:".len()..].trim().to_string())
            } else {
                None
            }
        });

        let authenticated = match proxy_auth {
            Some(ref auth_value) if auth_value.starts_with("Basic ") => {
                let encoded = &auth_value["Basic ".len()..];
                match base64::engine::general_purpose::STANDARD.decode(encoded) {
                    Ok(decoded_bytes) => {
                        let decoded = String::from_utf8_lossy(&decoded_bytes);
                        decoded.as_bytes().ct_eq(expected_token.as_bytes()).into()
                    }
                    Err(_) => false,
                }
            }
            _ => false,
        };

        if !authenticated {
            writer
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
                .await?;
            warn!("proxy auth failed: missing or invalid Proxy-Authorization header");
            return Ok(());
        }
    }

    // Reunite the stream halves.
    let reader = buf_reader.into_inner();
    let stream = reader
        .reunite(writer)
        .map_err(|_| anyhow::anyhow!("failed to reunite stream halves"))?;

    // Check if this domain needs tunneling
    debug!(host = %host, port, matched = domain_filter.matches(&host), "proxy: CONNECT target, checking domain filter");
    if !domain_filter.matches(&host) {
        // Direct passthrough — no secrets for this domain
        debug!(host = %host, port, "proxy: direct passthrough (domain filter miss)");
        let mut target = TcpStream::connect(format!("{}:{}", host, port))
            .await
            .context("connecting to target for direct passthrough")?;

        let (read_half, mut write_half) = stream.into_split();
        write_half
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .context("sending 200 to CONNECT client")?;

        let mut client_stream = read_half
            .reunite(write_half)
            .map_err(|_| anyhow::anyhow!("failed to reunite stream halves"))?;

        let _ = copy_bidirectional(&mut client_stream, &mut target).await;
        return Ok(());
    }

    // Send 200 Connection Established, then hand off to multiplexer.
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("sending 200 to CONNECT client")?;

    // Reunite again for the multiplexer (it expects a TcpStream).
    let stream = read_half
        .reunite(write_half)
        .map_err(|_| anyhow::anyhow!("failed to reunite stream halves"))?;

    let conn_id = mux
        .new_connection(stream, &host, port)
        .await
        .context("opening tunnel connection")?;

    debug!(conn_id, host = %host, port, "proxy: routing through tunnel (domain filter hit)");
    Ok(())
}

fn parse_host_port(target: &str) -> Result<(String, u16)> {
    // target = "host:port"
    let colon_pos = target
        .rfind(':')
        .ok_or_else(|| anyhow::anyhow!("missing port in CONNECT target: {}", target))?;
    let host = &target[..colon_pos];
    let port: u16 = target[colon_pos + 1..]
        .parse()
        .context(format!("invalid port in CONNECT target: {}", target))?;
    Ok((host.to_string(), port))
}
