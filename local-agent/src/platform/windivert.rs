//! WinDivert-based packet interception for transparent traffic redirection.
//!
//! Captures all outbound TCP:443 traffic at the packet level, rewrites the
//! destination to the local transparent listener,
//! and reverses the NAT on response packets. Works for ALL applications
//! regardless of proxy settings.
//!
//! Uses the WinDivert SOCKET layer in sniff mode for PID-based exclusion:
//! connections from excluded processes (e.g., the agent itself, the proxy server)
//! pass through without NAT. Sniff mode passively observes socket events without
//! blocking the originating connect() call, avoiding system-wide latency.
//! To close the race window where a SYN reaches the NETWORK handler before the
//! SOCKET tracker records the PID, the outbound handler retries the PID lookup
//! briefly on SYN packets whose source port is not yet in the map.
//!
//! Requires administrator privileges and the WinDivert driver.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tracing::{debug, error, info, trace, warn};
use windivert::layer;
use windivert::prelude::*;

/// Embedded WinDivert64.sys driver binary (extracted next to exe at runtime).
const WINDIVERT_SYS: &[u8] = include_bytes!("../../resources/WinDivert64.sys");

/// Raw FFI declarations for WinDivert functions not exposed by the Rust crate.
mod ffi {
    pub const WINDIVERT_SHUTDOWN_BOTH: u32 = 3;
    pub const DLL_PROCESS_ATTACH: u32 = 1;

    extern "system" {
        pub fn WinDivertShutdown(handle: isize, how: u32) -> i32;

        /// DLL entry point — with static linking, this is never called
        /// automatically. We call it manually to initialize the C-side TLS
        /// index used by WinDivertIoControl for overlapped I/O events.
        pub fn WinDivertDllEntry(module: isize, reason: u32, reserved: isize) -> i32;
    }
}

/// NAT table entry tracking the original destination for a connection.
struct NatEntry {
    original_dst_ip: IpAddr,
    original_dst_port: u16,
    /// Interface index of the original outbound packet (needed for reverse-NAT re-injection).
    original_interface_index: u32,
    /// Sub-interface index of the original outbound packet.
    original_subinterface_index: u32,
    last_seen: Instant,
}

/// NAT table key: (source IP, source port) of the client connection.
type NatKey = (IpAddr, u16);

/// Packet-level traffic interceptor using WinDivert.
///
/// Runs two NETWORK-layer OS threads (outbound + inbound) that capture and
/// NAT-rewrite packets, a SOCKET-layer thread for PID tracking (so excluded
/// processes like the proxy server bypass NAT), plus a cleanup thread for
/// stale NAT entries.
pub struct WinDivertInterceptor {
    nat_table: Arc<DashMap<NatKey, NatEntry>>,
    /// Maps local_port → PID for active outbound TCP:443 connections.
    socket_pid_map: Arc<DashMap<u16, u32>>,
    running: Arc<AtomicBool>,
    outbound_handle_raw: isize,
    inbound_handle_raw: isize,
    socket_handle_raw: isize,
    outbound_thread: Option<JoinHandle<()>>,
    inbound_thread: Option<JoinHandle<()>>,
    cleanup_thread: Option<JoinHandle<()>>,
    socket_thread: Option<JoinHandle<()>>,
}

impl WinDivertInterceptor {
    /// Extract the embedded WinDivert64.sys next to the running executable.
    ///
    /// Skips extraction if the file already exists with the correct size,
    /// avoiding unnecessary writes on every startup.
    fn ensure_driver_extracted() -> Result<()> {
        let exe_path = std::env::current_exe().context("getting current exe path")?;
        let driver_path = exe_path
            .parent()
            .context("getting exe directory")?
            .join("WinDivert64.sys");

        // Skip if already present with correct size
        if let Ok(meta) = std::fs::metadata(&driver_path) {
            if meta.len() == WINDIVERT_SYS.len() as u64 {
                debug!(path = %driver_path.display(), "WinDivert64.sys already present");
                return Ok(());
            }
            info!(path = %driver_path.display(), "WinDivert64.sys size mismatch, re-extracting");
        }

        std::fs::write(&driver_path, WINDIVERT_SYS)
            .with_context(|| format!("writing WinDivert64.sys to {}", driver_path.display()))?;
        info!(path = %driver_path.display(), size = WINDIVERT_SYS.len(), "extracted embedded WinDivert64.sys");
        Ok(())
    }

    /// Start the WinDivert interceptor.
    ///
    /// Opens NETWORK-layer handles (outbound + inbound) for packet NAT and a
    /// SOCKET-layer handle for PID tracking. Spawns dedicated OS threads for
    /// each.
    ///
    /// `tunnel_server_ips` is excluded from interception to prevent capturing the
    /// agent's own tunnel traffic (important when the tunnel uses port 443).
    ///
    /// `excluded_pids` lists process IDs whose outbound TCP:443 connections
    /// should pass through without NAT (e.g., the proxy server).
    pub fn start(
        transparent_port: u16,
        tunnel_server_ips: Vec<IpAddr>,
        excluded_pids: Vec<u32>,
    ) -> Result<Self> {
        info!("WinDivert interceptor starting");

        // Extract embedded WinDivert64.sys next to the exe if missing or outdated.
        Self::ensure_driver_extracted()?;

        // With static linking, the WinDivert C code's DllEntry is never called
        // automatically. We must call it to initialize the C-side TLS index
        // (windivert_tls_idx) used by WinDivertIoControl for overlapped I/O.
        // Without this, the C code uses TLS index 0 which belongs to another
        // component, causing silent data corruption or I/O failures.
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let ok = unsafe { ffi::WinDivertDllEntry(0, ffi::DLL_PROCESS_ATTACH, 0) };
            if ok == 0 {
                error!("WinDivertDllEntry initialization failed");
            }
        });

        let nat_table = Arc::new(DashMap::new());
        let socket_pid_map = Arc::new(DashMap::new());
        let running = Arc::new(AtomicBool::new(true));
        let excluded_pids = Arc::new(HashSet::from_iter(excluded_pids));

        // --- SOCKET layer: PID tracking (must open BEFORE network handles) ---
        // Each WinDivertOpen call runs on a dedicated sub-thread with a large
        // stack. The vendored C library's filter compiler + kernel driver
        // initialization consumes extreme stack space that overflows even a
        // 64 MB thread stack. Virtual memory reservation is cheap on 64-bit
        // Windows — only physically touched pages are committed.
        debug!("opening SOCKET layer handle");
        let socket_wd = on_large_stack(|| {
            WinDivert::socket(
                "outbound and remotePort == 443",
                -1,
                WinDivertFlags::new().set_sniff(),
            )
        })?
        .map_err(|e| anyhow::anyhow!("opening WinDivert socket handle: {e}"))?;
        debug!("SOCKET handle opened");
        let socket_handle_raw = unsafe { get_raw_handle(&socket_wd) };

        let pid_map_socket = Arc::clone(&socket_pid_map);
        let running_socket = Arc::clone(&running);
        let socket_thread = thread::Builder::new()
            .name("windivert-socket".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                run_socket_tracker(socket_wd, pid_map_socket, running_socket);
            })
            .context("spawning WinDivert socket thread")?;

        // --- NETWORK layer: packet NAT ---
        // Build outbound filter: capture all outbound TCP:443 IPv4+IPv6 traffic
        let mut ip_clauses = Vec::new();
        let v4_exclusion = tunnel_server_ips.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        });
        let v6_exclusion = tunnel_server_ips.iter().find_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            _ => None,
        });
        match v4_exclusion {
            Some(v4) => ip_clauses.push(format!("(ip and ip.DstAddr != {})", v4)),
            None => ip_clauses.push("ip".to_string()),
        };
        match v6_exclusion {
            Some(v6) => ip_clauses.push(format!("(ipv6 and ipv6.DstAddr != {})", v6)),
            None => ip_clauses.push("ipv6".to_string()),
        };
        let outbound_filter = format!(
            "outbound and tcp.DstPort == 443 and ({})",
            ip_clauses.join(" or ")
        );

        // Build response filter: capture responses from our transparent listener.
        // With hairpin NAT, the listener's source IP is the machine's own NIC
        // address (not 127.0.0.1), so we match only on port. Same-host traffic
        // is "outbound" in WinDivert, so no direction constraint either.
        // Packets without a NAT table entry are passed through unchanged.
        let inbound_filter = format!("(ip or ipv6) and tcp.SrcPort == {}", transparent_port);

        info!(
            outbound_filter = %outbound_filter,
            inbound_filter = %inbound_filter,
            excluded_pids = ?excluded_pids,
            "opening WinDivert handles"
        );

        // Open WinDivert network handles on dedicated sub-threads
        debug!("opening NETWORK outbound handle");
        let outbound_wd =
            on_large_stack(move || WinDivert::network(&outbound_filter, 0, WinDivertFlags::new()))?
                .map_err(|e| anyhow::anyhow!("opening WinDivert outbound handle: {e}"))?;
        debug!("opening NETWORK inbound handle");
        let inbound_wd =
            on_large_stack(move || WinDivert::network(&inbound_filter, 0, WinDivertFlags::new()))?
                .map_err(|e| anyhow::anyhow!("opening WinDivert inbound handle: {e}"))?;
        debug!("all WinDivert handles opened");

        // Save raw HANDLE values for cross-thread shutdown.
        // Safety: WinDivert<L>'s first field is `handle: HANDLE` (isize).
        let outbound_handle_raw = unsafe { get_raw_handle(&outbound_wd) };
        let inbound_handle_raw = unsafe { get_raw_handle(&inbound_wd) };

        // Spawn outbound capture thread
        let nat_out = Arc::clone(&nat_table);
        let running_out = Arc::clone(&running);
        let pid_map_out = Arc::clone(&socket_pid_map);
        let excluded_out = Arc::clone(&excluded_pids);
        let outbound_thread = thread::Builder::new()
            .name("windivert-outbound".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                run_outbound(
                    outbound_wd,
                    transparent_port,
                    nat_out,
                    running_out,
                    pid_map_out,
                    excluded_out,
                );
            })
            .context("spawning WinDivert outbound thread")?;

        // Spawn inbound capture thread
        let nat_in = Arc::clone(&nat_table);
        let running_in = Arc::clone(&running);
        let inbound_thread = thread::Builder::new()
            .name("windivert-inbound".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                run_inbound(inbound_wd, nat_in, running_in);
            })
            .context("spawning WinDivert inbound thread")?;

        // Spawn NAT table cleanup thread
        let nat_cleanup = Arc::clone(&nat_table);
        let running_cleanup = Arc::clone(&running);
        let cleanup_thread = thread::Builder::new()
            .name("windivert-cleanup".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                run_cleanup(nat_cleanup, running_cleanup);
            })
            .context("spawning WinDivert cleanup thread")?;

        info!("WinDivert interceptor started, all threads spawned");
        Ok(Self {
            nat_table,
            socket_pid_map,
            running,
            outbound_handle_raw,
            inbound_handle_raw,
            socket_handle_raw,
            outbound_thread: Some(outbound_thread),
            inbound_thread: Some(inbound_thread),
            cleanup_thread: Some(cleanup_thread),
            socket_thread: Some(socket_thread),
        })
    }

    /// Check if the interceptor threads are still running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the interceptor gracefully.
    ///
    /// Shuts down the WinDivert handles (unblocking pending recv calls),
    /// joins all threads, and clears the NAT table.
    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return; // already stopped
        }

        info!("stopping WinDivert interceptor");

        // Shutdown WinDivert handles to unblock blocking recv() in threads.
        // WinDivertShutdown is documented as thread-safe for this purpose.
        unsafe {
            ffi::WinDivertShutdown(self.socket_handle_raw, ffi::WINDIVERT_SHUTDOWN_BOTH);
            ffi::WinDivertShutdown(self.outbound_handle_raw, ffi::WINDIVERT_SHUTDOWN_BOTH);
            ffi::WinDivertShutdown(self.inbound_handle_raw, ffi::WINDIVERT_SHUTDOWN_BOTH);
        }

        if let Some(t) = self.socket_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.outbound_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.inbound_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.cleanup_thread.take() {
            let _ = t.join();
        }

        let remaining = self.nat_table.len();
        self.nat_table.clear();
        self.socket_pid_map.clear();
        info!(
            cleared_nat_entries = remaining,
            "WinDivert interceptor stopped"
        );
    }
}

impl Drop for WinDivertInterceptor {
    fn drop(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            self.stop();
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run a closure on a dedicated thread with pre-committed stack pages.
///
/// Rust's `thread::Builder::stack_size` only *reserves* virtual address space
/// — physical pages are committed on demand via guard-page faults. The vendored
/// WinDivert DLL is compiled with `/NODEFAULTLIB` (no CRT), so its code lacks
/// `__chkstk` stack probing. If a WinDivert function makes a stack access that
/// skips the guard page, the access hits uncommitted memory and Windows raises
/// STATUS_STACK_OVERFLOW instead of growing the stack.
///
/// Fix: allocate a large array from Rust (which *does* have `__chkstk`) at the
/// start of the thread. LLVM emits `__chkstk` for the allocation, probing every
/// page sequentially and forcing the OS to commit them. After the array goes out
/// of scope the pages stay committed, so subsequent FFI calls into WinDivert
/// find a fully usable stack.
/// Call a closure directly (no sub-thread).
///
/// Previous attempts to run WinDivertOpen on a dedicated thread with large
/// stack reservations (up to 512 MB) all hit STATUS_STACK_OVERFLOW on Windows
/// 11. The root cause appears to be in how the vendored WinDivert DLL interacts
/// with newly spawned threads. Calling WinDivertOpen on the *existing*
/// `windivert-init` thread (which already has a 64 MB stack created by
/// agent.rs) avoids the issue entirely.
fn on_large_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    Ok(f())
}

/// Extract the raw HANDLE value from a WinDivert instance.
///
/// # Safety
/// Relies on `WinDivert<L>` having `handle: HANDLE` as its first field,
/// where `HANDLE` is `#[repr(transparent)]` over `isize`.
unsafe fn get_raw_handle<L: WinDivertLayerTrait>(wd: &WinDivert<L>) -> isize {
    std::ptr::read((wd as *const WinDivert<L>).cast::<isize>())
}

/// SOCKET layer event loop: track PIDs of outbound TCP:443 connections.
///
/// The SOCKET handle is opened with the `sniff` flag, so `recv()` passively
/// observes socket events without blocking the originating `connect()` call.
/// The outbound handler compensates for the sniff-mode race by retrying the
/// PID lookup on SYN packets whose source port is not yet in the map.
fn run_socket_tracker(
    wd: WinDivert<layer::SocketLayer>,
    pid_map: Arc<DashMap<u16, u32>>,
    running: Arc<AtomicBool>,
) {
    info!("WinDivert socket tracker started");

    loop {
        match wd.recv(None) {
            Ok(packet) => {
                let event = packet.address.event();
                let local_port = packet.address.local_port();
                let pid = packet.address.process_id();

                match event {
                    WinDivertEvent::SocketConnect => {
                        trace!(local_port, pid, "socket connect tracked");
                        pid_map.insert(local_port, pid);
                    }
                    WinDivertEvent::SocketClose => {
                        pid_map.remove(&local_port);
                    }
                    _ => {} // Ignore bind/listen/accept
                }
            }
            Err(e) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                error!(error = ?e, "WinDivert socket recv error");
            }
        }
    }

    debug!("socket tracker thread exiting");
}

/// Outbound capture loop: intercept TCP:443, hairpin-NAT dst to transparent listener.
///
/// "Hairpin NAT": rewrites the destination to the packet's own source IP
/// (the machine's NIC address) instead of 127.0.0.1. This keeps the packet
/// on the same interface — no cross-interface routing or loopback RPF issues.
/// The transparent listener on 0.0.0.0 accepts connections on any local IP.
fn run_outbound(
    wd: WinDivert<layer::NetworkLayer>,
    transparent_port: u16,
    nat_table: Arc<DashMap<NatKey, NatEntry>>,
    running: Arc<AtomicBool>,
    socket_pid_map: Arc<DashMap<u16, u32>>,
    excluded_pids: Arc<HashSet<u32>>,
) {
    let mut buffer = vec![0u8; 65535];
    let port_bytes = transparent_port.to_be_bytes();

    info!("WinDivert outbound capture started");

    loop {
        match wd.recv(Some(&mut buffer)) {
            Ok(packet) => {
                let mut packet = packet.into_owned();
                let data = packet.data.to_mut();

                // Parse IP header for diagnostics and PID check
                let (pkt_src_ip, pkt_dst_ip, pkt_src_port, pkt_dst_port) = parse_packet_addrs(data);
                let is_syn = is_syn_packet(data);

                // Check PID exclusion before NAT rewriting. For SYN packets
                // whose source port isn't in the PID map yet (SOCKET sniff
                // race), retry briefly so the tracker thread can catch up.
                if should_exclude_with_retry(data, &socket_pid_map, &excluded_pids, is_syn) {
                    let _ = packet.recalculate_checksums(Default::default());
                    let _ = wd.send(&packet);
                    continue;
                }

                // Only intercept SYN (new connections) or packets with existing
                // NAT entries. Mid-stream packets from pre-existing connections
                // pass through to avoid disrupting them.
                if !is_syn && !nat_table.contains_key(&(pkt_src_ip, pkt_src_port)) {
                    let _ = packet.recalculate_checksums(Default::default());
                    let _ = wd.send(&packet);
                    continue;
                }

                let orig_iface = packet.address.interface_index();
                let orig_subiface = packet.address.subinterface_index();

                if is_syn {
                    debug!(
                        src = %format!("{}:{}", pkt_src_ip, pkt_src_port),
                        dst = %format!("{}:{}", pkt_dst_ip, pkt_dst_port),
                        "intercepting new TCP:443 connection"
                    );
                }

                if let Err(reason) =
                    rewrite_outbound(data, &port_bytes, &nat_table, orig_iface, orig_subiface)
                {
                    debug!(reason, "outbound not rewritten, passing through");
                }

                let _ = packet.recalculate_checksums(Default::default());
                if let Err(e) = wd.send(&packet) {
                    debug!(error = ?e, "outbound re-inject failed");
                }
            }
            Err(e) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                error!(error = ?e, "WinDivert outbound recv error");
            }
        }
    }

    debug!("outbound capture thread exiting");
}

/// Determine the byte offset where the TCP header starts.
/// Returns `None` for non-IP packets or packets too short to parse.
/// IPv4: variable header length (IHL field). IPv6: fixed 40 bytes.
fn tcp_header_offset(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    match data[0] >> 4 {
        4 => {
            let ihl = ((data[0] & 0x0F) as usize) * 4;
            if ihl >= 20 && data.len() >= ihl + 4 {
                Some(ihl)
            } else {
                None
            }
        }
        6 => {
            // IPv6 fixed header is always 40 bytes. Extension headers between
            // IPv6 and TCP are extremely rare for outbound TCP on Windows, and
            // WinDivert's filter engine already matched tcp.DstPort == 443.
            if data.len() >= 44 {
                Some(40)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if a packet's source port belongs to an excluded PID.
fn should_exclude(
    data: &[u8],
    socket_pid_map: &DashMap<u16, u32>,
    excluded_pids: &HashSet<u32>,
) -> bool {
    if excluded_pids.is_empty() {
        return false;
    }
    let tcp_off = match tcp_header_offset(data) {
        Some(off) => off,
        None => return false,
    };
    if data.len() < tcp_off + 2 {
        return false;
    }
    let src_port = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);

    if let Some(pid_entry) = socket_pid_map.get(&src_port) {
        if excluded_pids.contains(pid_entry.value()) {
            trace!(
                src_port,
                pid = *pid_entry.value(),
                "excluding packet from excluded PID"
            );
            return true;
        }
    }
    false
}

/// Like [`should_exclude`] but retries briefly for SYN packets whose source port
/// is not yet in the PID map — closing the SOCKET-sniff race window where a SYN
/// reaches the NETWORK handler before the tracker thread records the PID.
///
/// Only SYN packets with an *unknown* source port trigger retries; non-SYN packets
/// and SYNs whose PID is already tracked (but not excluded) return immediately.
fn should_exclude_with_retry(
    data: &[u8],
    socket_pid_map: &DashMap<u16, u32>,
    excluded_pids: &HashSet<u32>,
    is_syn: bool,
) -> bool {
    // Fast path — works for the vast majority of packets.
    if should_exclude(data, socket_pid_map, excluded_pids) {
        return true;
    }

    // Only retry for SYN packets when there are PIDs to exclude.
    if !is_syn || excluded_pids.is_empty() {
        return false;
    }

    // Determine source port.
    let tcp_off = match tcp_header_offset(data) {
        Some(off) => off,
        None => return false,
    };
    if data.len() < tcp_off + 2 {
        return false;
    }
    let src_port = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);

    // If PID is tracked but not excluded, no point retrying.
    if socket_pid_map.contains_key(&src_port) {
        return false;
    }

    // PID not tracked yet — SOCKET sniff race. Spin then yield.
    for _ in 0..100 {
        std::hint::spin_loop();
        if let Some(pid) = socket_pid_map.get(&src_port) {
            return excluded_pids.contains(pid.value());
        }
    }
    for _ in 0..10 {
        std::thread::yield_now();
        if let Some(pid) = socket_pid_map.get(&src_port) {
            return excluded_pids.contains(pid.value());
        }
    }

    false
}

/// Inbound capture loop: intercept responses from transparent listener, reverse NAT.
fn run_inbound(
    wd: WinDivert<layer::NetworkLayer>,
    nat_table: Arc<DashMap<NatKey, NatEntry>>,
    running: Arc<AtomicBool>,
) {
    let mut buffer = vec![0u8; 65535];

    info!("WinDivert inbound capture started");

    loop {
        match wd.recv(Some(&mut buffer)) {
            Ok(packet) => {
                let mut packet = packet.into_owned();
                let data = packet.data.to_mut();

                let is_syn_ack = is_syn_ack_packet(data);
                match rewrite_inbound(data, &nat_table) {
                    Ok((orig_iface, orig_subiface)) => {
                        packet.address.set_outbound(false);
                        packet.address.set_impostor(true);
                        packet.address.set_interface_index(orig_iface);
                        packet.address.set_subinterface_index(orig_subiface);
                    }
                    Err(_) => {
                        // Not our connection, pass through unchanged.
                        if is_syn_ack {
                            let (src, dst, sp, dp) = parse_packet_addrs(data);
                            warn!(
                                src = %format!("{}:{}", src, sp),
                                dst = %format!("{}:{}", dst, dp),
                                nat_entries = nat_table.len(),
                                "inbound SYN-ACK NAT miss — response not reverse-NATted"
                            );
                        }
                    }
                }

                let _ = packet.recalculate_checksums(Default::default());
                if let Err(e) = wd.send(&packet) {
                    debug!(error = ?e, "response re-inject failed");
                }
            }
            Err(e) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                error!(error = ?e, "WinDivert inbound recv error");
            }
        }
    }

    debug!("inbound capture thread exiting");
}

/// Rewrite an outbound IPv4 or IPv6 packet's destination using hairpin NAT.
///
/// Sets dst_ip = src_ip (the machine's own NIC address) and dst_port =
/// transparent_port. This "hairpin" keeps the packet on the same interface,
/// avoiding loopback routing issues on Windows. The transparent listener on
/// 0.0.0.0 accepts connections on any local IP.
///
/// Stores the original destination and interface info in the NAT table
/// keyed by (src_ip, src_port).
fn rewrite_outbound(
    data: &mut [u8],
    redirect_port: &[u8; 2],
    nat_table: &DashMap<NatKey, NatEntry>,
    interface_index: u32,
    subinterface_index: u32,
) -> Result<(), &'static str> {
    let tcp_off = tcp_header_offset(data).ok_or("packet too short or not IP")?;

    match data[0] >> 4 {
        4 => {
            // IPv4: src IP at [12..16], dst IP at [16..20]
            let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
            let src_port = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);
            let dst_port = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);

            nat_table.insert(
                (src_ip, src_port),
                NatEntry {
                    original_dst_ip: dst_ip,
                    original_dst_port: dst_port,
                    original_interface_index: interface_index,
                    original_subinterface_index: subinterface_index,
                    last_seen: Instant::now(),
                },
            );

            // Hairpin NAT: dst_ip = src_ip (no overlap: [12..16] vs [16..20])
            data[16] = data[12];
            data[17] = data[13];
            data[18] = data[14];
            data[19] = data[15];

            // Rewrite dst port
            data[tcp_off + 2] = redirect_port[0];
            data[tcp_off + 3] = redirect_port[1];
            Ok(())
        }
        6 => {
            // IPv6: src IP at [8..24], dst IP at [24..40]
            let src_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap()));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()));
            let src_port = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);
            let dst_port = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);

            nat_table.insert(
                (src_ip, src_port),
                NatEntry {
                    original_dst_ip: dst_ip,
                    original_dst_port: dst_port,
                    original_interface_index: interface_index,
                    original_subinterface_index: subinterface_index,
                    last_seen: Instant::now(),
                },
            );

            // Hairpin NAT: copy src [8..24] to dst [24..40] (no overlap)
            data.copy_within(8..24, 24);

            // Rewrite dst port
            data[tcp_off + 2] = redirect_port[0];
            data[tcp_off + 3] = redirect_port[1];
            Ok(())
        }
        _ => Err("not IPv4 or IPv6"),
    }
}

/// Reverse-NAT a response IPv4 or IPv6 packet from the transparent listener.
///
/// Looks up the original destination by (dst_ip, dst_port) — the client's
/// (src_ip, src_port) from the original outbound packet.
///
/// Returns the original interface index and sub-interface index so the caller
/// can re-inject the packet as inbound on the correct physical interface.
fn rewrite_inbound(
    data: &mut [u8],
    nat_table: &DashMap<NatKey, NatEntry>,
) -> Result<(u32, u32), &'static str> {
    let tcp_off = tcp_header_offset(data).ok_or("packet too short or not IP")?;

    match data[0] >> 4 {
        4 => {
            // IPv4: client (dst) IP at [16..20]
            let client_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
            let client_port = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);
            let key = (client_ip, client_port);

            if let Some(mut entry) = nat_table.get_mut(&key) {
                match entry.original_dst_ip {
                    IpAddr::V4(orig_v4) => {
                        let octets = orig_v4.octets();
                        data[12] = octets[0];
                        data[13] = octets[1];
                        data[14] = octets[2];
                        data[15] = octets[3];
                    }
                    _ => return Err("IPv4 packet but NAT entry has IPv6 address"),
                }
                let orig_port = entry.original_dst_port.to_be_bytes();
                data[tcp_off] = orig_port[0];
                data[tcp_off + 1] = orig_port[1];
                let iface = entry.original_interface_index;
                let subiface = entry.original_subinterface_index;
                entry.last_seen = Instant::now();
                Ok((iface, subiface))
            } else {
                Err("NAT table miss")
            }
        }
        6 => {
            // IPv6: client (dst) IP at [24..40]
            let client_ip =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()));
            let client_port = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);
            let key = (client_ip, client_port);

            if let Some(mut entry) = nat_table.get_mut(&key) {
                match entry.original_dst_ip {
                    IpAddr::V6(orig_v6) => {
                        data[8..24].copy_from_slice(&orig_v6.octets());
                    }
                    _ => return Err("IPv6 packet but NAT entry has IPv4 address"),
                }
                let orig_port = entry.original_dst_port.to_be_bytes();
                data[tcp_off] = orig_port[0];
                data[tcp_off + 1] = orig_port[1];
                let iface = entry.original_interface_index;
                let subiface = entry.original_subinterface_index;
                entry.last_seen = Instant::now();
                Ok((iface, subiface))
            } else {
                Err("NAT table miss")
            }
        }
        _ => Err("not IPv4 or IPv6"),
    }
}

/// Check if a packet is a TCP SYN (new connection initiation, not SYN-ACK).
fn is_syn_packet(data: &[u8]) -> bool {
    let tcp_off = match tcp_header_offset(data) {
        Some(off) => off,
        None => return false,
    };
    if data.len() < tcp_off + 14 {
        return false;
    }
    let flags = data[tcp_off + 13];
    (flags & 0x02 != 0) && (flags & 0x10 == 0) // SYN=1, ACK=0
}

/// Check if a packet is a TCP SYN-ACK.
fn is_syn_ack_packet(data: &[u8]) -> bool {
    let tcp_off = match tcp_header_offset(data) {
        Some(off) => off,
        None => return false,
    };
    if data.len() < tcp_off + 14 {
        return false;
    }
    let flags = data[tcp_off + 13];
    (flags & 0x02 != 0) && (flags & 0x10 != 0) // SYN=1, ACK=1
}

/// Parse src/dst IP and ports from an IPv4 or IPv6 packet for diagnostic logging.
fn parse_packet_addrs(data: &[u8]) -> (IpAddr, IpAddr, u16, u16) {
    let unspec = (
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0u16,
        0u16,
    );
    let tcp_off = match tcp_header_offset(data) {
        Some(off) => off,
        None => return unspec,
    };
    match data[0] >> 4 {
        4 => {
            let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
            let sp = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);
            let dp = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);
            (src, dst, sp, dp)
        }
        6 => {
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap()));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()));
            let sp = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);
            let dp = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);
            (src, dst, sp, dp)
        }
        _ => unspec,
    }
}

/// Periodically remove stale NAT entries (connections closed/abandoned > 5 minutes ago).
fn run_cleanup(nat_table: Arc<DashMap<NatKey, NatEntry>>, running: Arc<AtomicBool>) {
    const CLEANUP_INTERVAL_SECS: u64 = 60;
    const MAX_AGE: Duration = Duration::from_secs(300); // 5 minutes
    const CHECK_INTERVAL: Duration = Duration::from_secs(1);

    let mut ticks: u64 = 0;

    while running.load(Ordering::Relaxed) {
        thread::sleep(CHECK_INTERVAL);
        ticks += 1;

        if ticks % CLEANUP_INTERVAL_SECS == 0 {
            let before = nat_table.len();
            nat_table.retain(|_, entry| entry.last_seen.elapsed() < MAX_AGE);
            let removed = before - nat_table.len();
            if removed > 0 {
                debug!(removed, remaining = nat_table.len(), "NAT table cleanup");
            }
        }
    }

    debug!("cleanup thread exiting");
}
