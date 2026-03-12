//! WinDivert-based packet interception for transparent traffic redirection.
//!
//! Captures all outbound TCP:443 traffic at the packet level, rewrites the
//! destination to the local transparent listener (127.0.0.1:transparent_port),
//! and reverses the NAT on response packets. Works for ALL applications
//! regardless of proxy settings.
//!
//! Uses the WinDivert SOCKET layer in sniff mode for PID-based exclusion:
//! connections from excluded processes (e.g., the proxy server) pass through
//! without NAT. Sniff mode passively observes socket events without blocking
//! the originating connect() call, avoiding system-wide latency on every new
//! connection. The trade-off is a small race window where a SYN could reach
//! the NETWORK handler before the PID mapping is recorded; in practice this
//! is negligible because the SOCKET event fires before the TCP handshake
//! completes.
//!
//! Requires administrator privileges and the WinDivert driver.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tracing::{debug, error, info, trace};
use windivert::prelude::*;
use windivert::layer;

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
    original_dst_ip: Ipv4Addr,
    original_dst_port: u16,
    /// Interface index of the original outbound packet (needed for reverse-NAT re-injection).
    original_interface_index: u32,
    /// Sub-interface index of the original outbound packet.
    original_subinterface_index: u32,
    last_seen: Instant,
}

/// NAT table key: (source IP, source port) of the client connection.
type NatKey = (Ipv4Addr, u16);

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
    /// Start the WinDivert interceptor.
    ///
    /// Opens NETWORK-layer handles (outbound + inbound) for packet NAT and a
    /// SOCKET-layer handle for PID tracking. Spawns dedicated OS threads for
    /// each.
    ///
    /// `tunnel_server_ip` is excluded from interception to prevent capturing the
    /// agent's own tunnel traffic (important when the tunnel uses port 443).
    ///
    /// `excluded_pids` lists process IDs whose outbound TCP:443 connections
    /// should pass through without NAT (e.g., the proxy server).
    pub fn start(
        transparent_port: u16,
        tunnel_server_ip: Option<Ipv4Addr>,
        excluded_pids: Vec<u32>,
    ) -> Result<Self> {
        eprintln!("[windivert] start() entry");

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
        eprintln!("[windivert] opening SOCKET layer handle (on dedicated thread)");
        let socket_wd = on_large_stack(|| {
            WinDivert::socket("outbound and remotePort == 443", -1, WinDivertFlags::new().set_sniff())
        })?.map_err(|e| anyhow::anyhow!("opening WinDivert socket handle: {e}"))?;
        eprintln!("[windivert] SOCKET handle opened");
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
        // Build outbound filter: capture all outbound TCP:443 IPv4 traffic
        let outbound_filter = match tunnel_server_ip {
            Some(ip) => format!(
                "outbound and tcp.DstPort == 443 and ip and ip.DstAddr != {}",
                ip
            ),
            None => "outbound and tcp.DstPort == 443 and ip".to_string(),
        };

        // Build response filter: capture responses from our transparent listener.
        // With hairpin NAT, the listener's source IP is the machine's own NIC
        // address (not 127.0.0.1), so we match only on port. Same-host traffic
        // is "outbound" in WinDivert, so no direction constraint either.
        // Packets without a NAT table entry are passed through unchanged.
        let inbound_filter = format!(
            "ip and tcp.SrcPort == {}",
            transparent_port
        );

        info!(
            outbound_filter = %outbound_filter,
            inbound_filter = %inbound_filter,
            excluded_pids = ?excluded_pids,
            "opening WinDivert handles"
        );

        // Open WinDivert network handles on dedicated sub-threads
        eprintln!("[windivert] opening NETWORK outbound handle (on dedicated thread)");
        let outbound_wd = on_large_stack(move || {
            WinDivert::network(&outbound_filter, 0, WinDivertFlags::new())
        })?.map_err(|e| anyhow::anyhow!("opening WinDivert outbound handle: {e}"))?;
        eprintln!("[windivert] opening NETWORK inbound handle (on dedicated thread)");
        let inbound_wd = on_large_stack(move || {
            WinDivert::network(&inbound_filter, 0, WinDivertFlags::new())
        })?.map_err(|e| anyhow::anyhow!("opening WinDivert inbound handle: {e}"))?;
        eprintln!("[windivert] all handles opened");

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
                run_outbound(outbound_wd, transparent_port, nat_out, running_out, pid_map_out, excluded_out);
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

        eprintln!("[windivert] all threads spawned, returning interceptor");
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
        info!(cleared_nat_entries = remaining, "WinDivert interceptor stopped");
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
fn on_large_stack<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
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
/// This avoids adding latency to every outbound connection system-wide, at the
/// cost of a small race window where a SYN could arrive at the NETWORK handler
/// before the PID mapping is recorded. In practice the race is negligible.
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
                let (pkt_src_ip, pkt_dst_ip, pkt_src_port, pkt_dst_port) =
                    parse_packet_addrs(data);

                // Check PID exclusion before NAT rewriting.
                if should_exclude(data, &socket_pid_map, &excluded_pids) {
                    let _ = packet.recalculate_checksums(Default::default());
                    let _ = wd.send(&packet);
                    continue;
                }

                // Only intercept SYN (new connections) or packets with existing
                // NAT entries. Mid-stream packets from pre-existing connections
                // pass through to avoid disrupting them.
                let is_syn = is_syn_packet(data);
                if !is_syn && !nat_table.contains_key(&(pkt_src_ip, pkt_src_port)) {
                    let _ = packet.recalculate_checksums(Default::default());
                    let _ = wd.send(&packet);
                    continue;
                }

                let orig_iface = packet.address.interface_index();
                let orig_subiface = packet.address.subinterface_index();

                if is_syn {
                    info!(
                        src = %format!("{}:{}", pkt_src_ip, pkt_src_port),
                        dst = %format!("{}:{}", pkt_dst_ip, pkt_dst_port),
                        "intercepting new TCP:443 connection"
                    );
                }

                if let Err(reason) = rewrite_outbound(data, &port_bytes, &nat_table, orig_iface, orig_subiface) {
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

/// Check if a packet's source port belongs to an excluded PID.
fn should_exclude(
    data: &[u8],
    socket_pid_map: &DashMap<u16, u32>,
    excluded_pids: &HashSet<u32>,
) -> bool {
    if excluded_pids.is_empty() {
        return false;
    }

    // Parse src_port: need at least IP header + 2 bytes of TCP
    if data.len() < 22 {
        return false;
    }
    if (data[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl + 2 {
        return false;
    }
    let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);

    if let Some(pid_entry) = socket_pid_map.get(&src_port) {
        if excluded_pids.contains(pid_entry.value()) {
            trace!(src_port, pid = *pid_entry.value(), "excluding packet from excluded PID");
            return true;
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

                match rewrite_inbound(data, &nat_table) {
                    Ok((orig_iface, orig_subiface)) => {
                        packet.address.set_outbound(false);
                        packet.address.set_impostor(true);
                        packet.address.set_interface_index(orig_iface);
                        packet.address.set_subinterface_index(orig_subiface);
                    }
                    Err(_) => {} // Not our connection, pass through unchanged.
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

/// Rewrite an outbound packet's destination using hairpin NAT.
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
    // Minimum: 20-byte IP header + 4 bytes for TCP ports
    if data.len() < 24 {
        return Err("packet too short");
    }
    if (data[0] >> 4) != 4 {
        return Err("not IPv4");
    }

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl + 4 {
        return Err("invalid IHL");
    }

    // Read original addresses and ports
    // IPv4: src IP at [12..16], dst IP at [16..20]
    // TCP: src port at [ihl..ihl+2], dst port at [ihl+2..ihl+4]
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
    let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

    // Store NAT mapping: (client_ip, client_port) → original destination + interface
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

    // Hairpin NAT: rewrite destination IP to source IP (machine's own address).
    // Must read src bytes before writing to dst (no overlap: [12..16] vs [16..20]).
    data[16] = data[12];
    data[17] = data[13];
    data[18] = data[14];
    data[19] = data[15];

    // Rewrite destination port to transparent listener port
    data[ihl + 2] = redirect_port[0];
    data[ihl + 3] = redirect_port[1];

    Ok(())
}

/// Reverse-NAT a response packet from the transparent listener.
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
    if data.len() < 24 {
        return Err("packet too short");
    }
    if (data[0] >> 4) != 4 {
        return Err("not IPv4");
    }

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl + 4 {
        return Err("invalid IHL");
    }

    // For responses: dst is the original client (our NAT key)
    let client_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let client_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
    let key = (client_ip, client_port);

    if let Some(mut entry) = nat_table.get_mut(&key) {
        // Restore original server IP as packet source
        let orig_ip = entry.original_dst_ip.octets();
        data[12] = orig_ip[0];
        data[13] = orig_ip[1];
        data[14] = orig_ip[2];
        data[15] = orig_ip[3];

        // Restore original server port as source port
        let orig_port = entry.original_dst_port.to_be_bytes();
        data[ihl] = orig_port[0];
        data[ihl + 1] = orig_port[1];

        let iface = entry.original_interface_index;
        let subiface = entry.original_subinterface_index;
        entry.last_seen = Instant::now();
        Ok((iface, subiface))
    } else {
        Err("NAT table miss")
    }
}

/// Check if a packet is a TCP SYN (new connection initiation, not SYN-ACK).
fn is_syn_packet(data: &[u8]) -> bool {
    if data.len() < 34 || (data[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl + 14 {
        return false;
    }
    let flags = data[ihl + 13];
    (flags & 0x02 != 0) && (flags & 0x10 == 0) // SYN=1, ACK=0
}

/// Parse src/dst IP and ports from an IPv4 packet for diagnostic logging.
fn parse_packet_addrs(data: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16) {
    if data.len() < 24 || (data[0] >> 4) != 4 {
        return (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0);
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl + 4 {
        return (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0);
    }
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let sp = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
    let dp = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
    (src, dst, sp, dp)
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
