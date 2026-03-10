use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::config::LocalProxyConfig;
use crate::tunnel::multiplexer::Multiplexer;

/// Run the local HTTP CONNECT proxy.
/// Users point HTTPS_PROXY=http://127.0.0.1:19080 at this.
pub async fn run_local_proxy(
    config: &LocalProxyConfig,
    multiplexer: Arc<Multiplexer>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("binding local proxy on {}", addr))?;
    info!(addr = %addr, "local CONNECT proxy listening");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        debug!(peer = %peer, "accepted local connection");
                        let mux = multiplexer.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connect(stream, mux).await {
                                warn!(peer = %peer, error = %e, "CONNECT handling failed");
                            }
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
async fn handle_connect(stream: TcpStream, mux: Arc<Multiplexer>) -> Result<()> {
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

    // Consume remaining headers until empty line.
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Reunite the stream halves.
    let reader = buf_reader.into_inner();
    let stream = reader
        .reunite(writer)
        .map_err(|_| anyhow::anyhow!("failed to reunite stream halves"))?;

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

    debug!(conn_id, host = %host, port, "CONNECT tunnel established");
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
