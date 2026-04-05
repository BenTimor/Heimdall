use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::config::AgentConfig;
use crate::domain_filter::DomainFilter;
use crate::health::{self, HealthState};
use crate::local_proxy;
use crate::transparent;
use crate::tunnel::client;
use crate::tunnel::multiplexer::Multiplexer;

/// Run the agent: connect tunnel, start services, reconnect on tunnel death.
///
/// The outer loop handles reconnection: when the tunnel dies (read/write/heartbeat
/// loop exits), the agent stops WinDivert (to unblock traffic), tears down the
/// current session's services, reconnects, and restarts everything.
///
/// The domain filter is shared across reconnections so that cached domain lists
/// survive brief disconnects. The ctrl-c shutdown channel spans the entire lifetime.
pub async fn run(config: AgentConfig) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Domain filter is shared across reconnections — cached domains survive
    // brief tunnel outages.
    let domain_filter = Arc::new(DomainFilter::new());
    let max_connections = config.tunnel.as_ref().map_or(1000, |t| t.max_connections);

    // On Linux, re-apply transparent interception rules if they were lost after
    // reboot. This runs once at startup, not per-session.
    #[cfg(target_os = "linux")]
    if config.transparent.enabled {
        log_linux_transparent_caveats();
        reapply_linux_interception_if_needed(&config);
    }

    // Spawn ctrl-c handler that signals the top-level shutdown.
    // shutdown_tx is moved into the spawned task — it is the sole owner.
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("ctrl-c received, shutting down...");
            let _ = shutdown_tx.send(true);
        }
    });

    // Initial connection
    info!("connecting to tunnel server...");
    let initial_framed = Box::pin(client::connect_with_reconnect(
        &config.server,
        &config.auth,
        &config.reconnect,
        shutdown_rx.clone(),
    ))
    .await
    .context("initial tunnel connection")?;

    let started_at = Instant::now();
    let mut pending_framed: Option<_> = Some(initial_framed);

    // === Reconnect loop ===
    loop {
        // Take the framed tunnel for this session (always Some at loop entry).
        let framed = pending_framed
            .take()
            .expect("pending_framed must be Some at loop start");

        // Per-session shutdown channel: signals services to stop when the tunnel
        // dies or when the top-level shutdown fires.
        let (session_shutdown_tx, session_shutdown_rx) = tokio::sync::watch::channel(false);

        // Forward top-level shutdown to session shutdown.
        let mut top_shutdown_for_forward = shutdown_rx.clone();
        let session_tx_for_forward = session_shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = top_shutdown_for_forward.changed().await;
            let _ = session_tx_for_forward.send(true);
        });

        // Start multiplexer
        let multiplexer = Multiplexer::start(
            framed,
            session_shutdown_rx.clone(),
            max_connections,
            domain_filter.clone(),
            config.auth.machine_id.clone(),
        );
        let mut tunnel_alive = multiplexer.subscribe_tunnel_alive();

        // Request initial domain list and start polling
        if let Err(e) = multiplexer.request_domain_list().await {
            warn!(error = %e, "failed to send initial domain list request");
        }

        let poll_mux = multiplexer.clone();
        let mut poll_shutdown = session_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.tick().await; // skip immediate first tick (already sent above)
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = poll_mux.request_domain_list().await {
                            warn!(error = %e, "domain list polling failed, tunnel may be down");
                            break;
                        }
                    }
                    _ = poll_shutdown.changed() => {
                        break;
                    }
                }
            }
        });

        // Start health endpoint
        let health_state = Arc::new(HealthState {
            multiplexer: multiplexer.clone(),
            started_at,
        });
        let health_config = config.health.clone();
        let health_shutdown = session_shutdown_rx.clone();
        let health_handle = tokio::spawn(async move {
            if let Err(e) =
                health::run_health_server(&health_config, health_state, health_shutdown).await
            {
                error!(error = %e, "health server error");
            }
        });

        // Start local CONNECT proxy
        let proxy_config = config.local_proxy.clone();
        let proxy_mux = multiplexer.clone();
        let proxy_shutdown = session_shutdown_rx.clone();
        let proxy_domain_filter = domain_filter.clone();
        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = local_proxy::run_local_proxy(
                &proxy_config,
                proxy_mux,
                proxy_shutdown,
                proxy_domain_filter,
            )
            .await
            {
                error!(error = %e, "local proxy error");
            }
        });

        // Optionally start transparent listener
        let transparent_handle = if config.transparent.enabled {
            let transparent_config = config.transparent.clone();
            let transparent_mux = multiplexer.clone();
            let transparent_shutdown = session_shutdown_rx.clone();
            let transparent_domain_filter = domain_filter.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = transparent::run_transparent_listener(
                    &transparent_config,
                    transparent_mux,
                    transparent_shutdown,
                    transparent_domain_filter,
                )
                .await
                {
                    error!(error = %e, "transparent listener error");
                }
            }))
        } else {
            None
        };

        // On Windows, optionally start WinDivert packet-level interception.
        #[cfg(target_os = "windows")]
        let windivert_interceptor = if config.transparent.enabled {
            let wd_config = config.clone();
            std::thread::Builder::new()
                .name("windivert-init".into())
                .stack_size(64 * 1024 * 1024)
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

        // === Wait for tunnel death or top-level shutdown ===
        let mut top_shutdown_rx = shutdown_rx.clone();
        let should_exit = loop {
            tokio::select! {
                result = tunnel_alive.changed() => {
                    match result {
                        Ok(()) if !*tunnel_alive.borrow() => {
                            warn!("tunnel connection lost, initiating reconnection");
                            break false; // reconnect
                        }
                        Ok(()) => {
                            // Spurious wake (value still true) — keep waiting
                        }
                        Err(_) => {
                            // watch sender dropped — all tunnel tasks exited
                            warn!("tunnel connection lost (sender dropped), initiating reconnection");
                            break false;
                        }
                    }
                }
                _ = top_shutdown_rx.changed() => {
                    break true; // clean exit
                }
            }
        };

        // --- Tear down current session ---

        // Stop WinDivert FIRST — must not block traffic while tunnel is dead
        #[cfg(target_os = "windows")]
        if let Some(mut interceptor) = windivert_interceptor {
            info!("stopping WinDivert interceptor");
            interceptor.stop();
        }

        // Gracefully drain active connections
        multiplexer.shutdown().await;

        // Signal session services to stop
        let _ = session_shutdown_tx.send(true);

        // Wait for session services to finish
        let _ = health_handle.await;
        let _ = proxy_handle.await;
        if let Some(handle) = transparent_handle {
            let _ = handle.await;
        }

        if should_exit {
            info!("agent stopped");
            return Ok(());
        }

        // --- Reconnect ---
        info!("reconnecting to tunnel server...");
        match Box::pin(client::connect_with_reconnect(
            &config.server,
            &config.auth,
            &config.reconnect,
            shutdown_rx.clone(),
        ))
        .await
        {
            Ok(new_framed) => {
                info!("tunnel reconnected successfully");
                pending_framed = Some(new_framed);
                // Loop back to start a new session
            }
            Err(e) => {
                // connect_with_reconnect only fails on shutdown signal
                info!(error = %e, "reconnection aborted (shutdown requested)");
                return Ok(());
            }
        }
    }
}

/// Re-apply Linux transparent interception rules if they were lost after reboot.
/// iptables/ip6tables rules are not persistent by default.
#[cfg(target_os = "linux")]
fn reapply_linux_interception_if_needed(config: &AgentConfig) {
    match crate::state::InstallState::load() {
        Ok(Some(state)) if state.interception_enabled => {
            let platform = crate::platform::platform();
            match platform.is_interception_active() {
                Ok(false) => {
                    if let Err(e) = platform.enable_interception(config.transparent.port) {
                        warn!(error = %e, "failed to re-apply interception rules");
                    } else {
                        info!("Re-applied interception rules (lost after reboot)");
                    }
                }
                Ok(true) => {
                    // Rules are already active, nothing to do.
                }
                Err(e) => {
                    warn!(error = %e, "failed to check interception status");
                }
            }
        }
        Ok(_) => {
            // No state or interception not enabled — skip.
        }
        Err(e) => {
            warn!(error = %e, "failed to load install state for interception check");
        }
    }
}

#[cfg(target_os = "linux")]
fn log_linux_transparent_caveats() {
    info!(
        "linux transparent mode redirects outbound IPv4 and IPv6 traffic with iptables/ip6tables"
    );

    if linux_running_as_root() {
        warn!(
            "linux transparent mode excludes root-owned client processes; verify from a non-root shell or use explicit proxy mode for root/system daemons"
        );
    }
}

#[cfg(target_os = "linux")]
fn linux_running_as_root() -> bool {
    use std::process::Command;

    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| {
            let uid = String::from_utf8(output.stdout).ok()?;
            uid.trim().parse::<u32>().ok()
        })
        == Some(0)
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
    use std::net::IpAddr;

    if config.transparent.method == InterceptionMethod::SystemProxy {
        info!("interception method is system_proxy, skipping WinDivert");
        return None;
    }

    // Resolve tunnel server IP(s) for WinDivert filter exclusion.
    // If the host is a hostname (not an IP), try DNS resolution.
    let tunnel_server_ips: Vec<IpAddr> = {
        let mut ips = Vec::new();
        if let Ok(ip) = config.server.host.parse::<IpAddr>() {
            ips.push(ip);
        } else {
            use std::net::ToSocketAddrs;
            let addr_str = format!("{}:0", config.server.host);
            if let Ok(addrs) = addr_str.to_socket_addrs() {
                for a in addrs {
                    ips.push(a.ip());
                }
                ips.sort_unstable();
                ips.dedup();
            }
        }
        ips
    };

    if tunnel_server_ips.is_empty() && config.server.port == 443 {
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
        info!(
            proxy_pid,
            port = config.server.port,
            "auto-detected proxy server PID"
        );
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

    match WinDivertInterceptor::start(config.transparent.port, tunnel_server_ips, excluded_pids) {
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
