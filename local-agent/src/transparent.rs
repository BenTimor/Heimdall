use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::config::TransparentConfig;
use crate::sni;
use crate::tunnel::multiplexer::Multiplexer;

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
) -> Result<()> {
    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("binding transparent listener on {}", addr))?;
    info!(addr = %addr, "transparent listener started");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        debug!(peer = %peer, "accepted transparent connection");
                        let mux = multiplexer.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_transparent(stream, mux).await {
                                debug!(peer = %peer, error = %e, "transparent connection failed");
                            }
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

    debug!(hostname = %hostname, "extracted SNI from transparent connection");

    let conn_id = mux
        .new_connection(stream, &hostname, 443)
        .await
        .context("opening tunnel connection for transparent stream")?;

    debug!(conn_id, hostname = %hostname, "transparent tunnel established");
    Ok(())
}
