use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::config::AgentConfig;
use crate::health::{self, HealthState};
use crate::local_proxy;
use crate::transparent;
use crate::tunnel::client;
use crate::tunnel::multiplexer::Multiplexer;

/// Run the agent: connect tunnel, start local proxy, health endpoint, event loop.
pub async fn run(config: AgentConfig) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Connect to tunnel with reconnect.
    // Box::pin the TLS handshake future — it creates a large async state machine
    // (TlsConnector::connect + Framed codec) that would otherwise inflate this
    // function's state machine by several MB.
    info!("connecting to tunnel server...");
    let framed = Box::pin(client::connect_with_reconnect(
        &config.server,
        &config.auth,
        &config.reconnect,
        shutdown_rx.clone(),
    ))
    .await
    .context("initial tunnel connection")?;

    let started_at = Instant::now();

    // Start multiplexer
    let multiplexer = Multiplexer::start(framed, shutdown_rx.clone());

    // Start health endpoint
    let health_state = Arc::new(HealthState {
        multiplexer: multiplexer.clone(),
        machine_id: config.auth.machine_id.clone(),
        started_at,
    });

    let health_config = config.health.clone();
    let health_shutdown = shutdown_rx.clone();
    let health_handle = tokio::spawn(async move {
        if let Err(e) = health::run_health_server(&health_config, health_state, health_shutdown).await {
            error!(error = %e, "health server error");
        }
    });

    // Start local CONNECT proxy
    let proxy_config = config.local_proxy.clone();
    let proxy_mux = multiplexer.clone();
    let proxy_shutdown = shutdown_rx.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = local_proxy::run_local_proxy(&proxy_config, proxy_mux, proxy_shutdown).await {
            error!(error = %e, "local proxy error");
        }
    });

    // Optionally start transparent listener (for OS-level interception)
    let transparent_handle = if config.transparent.enabled {
        let transparent_config = config.transparent.clone();
        let transparent_mux = multiplexer.clone();
        let transparent_shutdown = shutdown_rx.clone();
        Some(tokio::spawn(async move {
            if let Err(e) =
                transparent::run_transparent_listener(&transparent_config, transparent_mux, transparent_shutdown)
                    .await
            {
                error!(error = %e, "transparent listener error");
            }
        }))
    } else {
        None
    };

    // On Windows, optionally start WinDivert packet-level interception.
    // Run on a dedicated thread: the main thread's stack is shared with the
    // async runtime polling chain, and WinDivert's kernel handle creation +
    // filter compilation adds enough stack pressure to cause overflow.
    #[cfg(target_os = "windows")]
    let windivert_interceptor = if config.transparent.enabled {
        let wd_config = config.clone();
        std::thread::Builder::new()
            .name("windivert-init".into())
            .stack_size(64 * 1024 * 1024) // 64 MB virtual reservation — only touched pages commit physical memory
            .spawn(move || start_windivert_if_configured(&wd_config))
            .expect("failed to spawn WinDivert init thread")
            .join()
            .expect("WinDivert init thread panicked")
    } else {
        None
    };

    info!(
        proxy_addr = %format!("{}:{}", config.local_proxy.host, config.local_proxy.port),
        health_addr = %format!("{}:{}", config.health.host, config.health.port),
        transparent = config.transparent.enabled,
        "agent running"
    );

    // Wait for ctrl-c
    tokio::signal::ctrl_c()
        .await
        .context("waiting for ctrl-c")?;

    info!("shutting down...");

    // Stop WinDivert before signaling async tasks (it uses OS threads, not tokio)
    #[cfg(target_os = "windows")]
    if let Some(mut interceptor) = windivert_interceptor {
        interceptor.stop();
    }

    let _ = shutdown_tx.send(true);

    // Wait for async tasks to finish
    if let Some(handle) = transparent_handle {
        let _ = tokio::join!(proxy_handle, health_handle, handle);
    } else {
        let _ = tokio::join!(proxy_handle, health_handle);
    }

    info!("agent stopped");
    Ok(())
}

/// Try to start WinDivert packet interception based on config.
///
/// Returns `None` if interception method is `SystemProxy`, or if WinDivert
/// fails to start (with a warning in `Auto` mode, error in `Windivert` mode).
///
/// Auto-detects the proxy server PID (via netstat on the tunnel port) and
/// excludes it from interception to prevent redirect loops when the proxy
/// runs on the same machine.
#[cfg(target_os = "windows")]
fn start_windivert_if_configured(
    config: &AgentConfig,
) -> Option<crate::platform::windivert::WinDivertInterceptor> {
    use crate::config::InterceptionMethod;
    use crate::platform::windivert::WinDivertInterceptor;
    use std::net::Ipv4Addr;

    if config.transparent.method == InterceptionMethod::SystemProxy {
        info!("interception method is system_proxy, skipping WinDivert");
        return None;
    }

    // Resolve tunnel server IP for WinDivert filter exclusion.
    // If the host is a hostname (not an IP), try DNS resolution.
    let tunnel_server_ip: Option<Ipv4Addr> = config
        .server
        .host
        .parse::<Ipv4Addr>()
        .ok()
        .or_else(|| {
            use std::net::ToSocketAddrs;
            let addr_str = format!("{}:0", config.server.host);
            addr_str.to_socket_addrs().ok().and_then(|mut addrs| {
                addrs.find_map(|a| match a {
                    std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                    _ => None,
                })
            })
        });

    if tunnel_server_ip.is_none() && config.server.port == 443 {
        warn!(
            host = %config.server.host,
            "could not resolve tunnel server IP and tunnel port is 443 — \
             WinDivert may intercept tunnel traffic causing a loop"
        );
    }

    // Build excluded PID list: agent self + config overrides + auto-detected proxy PID
    let mut excluded_pids: Vec<u32> = config.transparent.exclude_pids.clone();
    excluded_pids.push(std::process::id());

    if let Some(proxy_pid) = find_pid_listening_on(config.server.port) {
        info!(proxy_pid, port = config.server.port, "auto-detected proxy server PID");
        excluded_pids.push(proxy_pid);
    } else {
        warn!(
            port = config.server.port,
            "could not auto-detect proxy server PID — \
             if the proxy is local, its outbound connections may loop"
        );
    }

    excluded_pids.sort_unstable();
    excluded_pids.dedup();
    info!(excluded_pids = ?excluded_pids, "WinDivert PID exclusion list");

    match WinDivertInterceptor::start(config.transparent.port, tunnel_server_ip, excluded_pids) {
        Ok(interceptor) => {
            info!("WinDivert interceptor started — capturing all outbound TCP:443 traffic");
            Some(interceptor)
        }
        Err(e) => {
            match config.transparent.method {
                InterceptionMethod::Auto => {
                    warn!(
                        error = %e,
                        "WinDivert unavailable, falling back to system proxy only"
                    );
                }
                InterceptionMethod::Windivert => {
                    error!(
                        error = %e,
                        "WinDivert failed to start (explicitly configured)"
                    );
                }
                _ => {}
            }
            None
        }
    }
}

/// Find the PID of the process listening on a given TCP port.
///
/// Parses `netstat -ano -p tcp` output. Returns `None` if no process is found.
#[cfg(target_os = "windows")]
fn find_pid_listening_on(port: u16) -> Option<u32> {
    let output = std::process::Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let port_str = format!(":{}", port);

    for line in stdout.lines() {
        // Match lines like:  TCP  0.0.0.0:8443  0.0.0.0:0  LISTENING  12345
        if !line.contains("LISTENING") {
            continue;
        }
        // Check if the local address column contains our port
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let local_addr = parts[1];
            if local_addr.ends_with(&port_str) {
                return parts[4].parse().ok();
            }
        }
    }
    None
}
