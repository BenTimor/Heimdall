# Guardian Local Agent

Rust daemon that tunnels HTTPS traffic from developer machines to the Guardian proxy server for secret injection. Supports both explicit proxy mode (`HTTPS_PROXY`) and transparent interception (no app configuration needed).

> **Keep this file updated** when adding modules, changing architecture, or discovering new patterns.

## Quick Reference

```bash
cargo build --release     # build
cargo test                # run tests (36 passing)
cargo run -- run          # start agent (default config)
cargo run -- test         # test tunnel connectivity
cargo run -- status       # query health endpoint
cargo run -- install      # install CA cert + enable interception
cargo run -- uninstall    # reverse all install actions
cargo run -- service start/stop/status  # manage system service
cargo install cargo-audit   # one-time install
cargo audit                 # check for dependency vulnerabilities
```

## Architecture

```
Mode 1: Explicit Proxy (HTTPS_PROXY)
App → CONNECT → LocalProxy (19080)
  └── Parse CONNECT host:port → Send 200 → Hand off to Multiplexer

Mode 2: Transparent Interception
OS redirect (TCP:443) → TransparentListener (0.0.0.0:19443)
  └── peek() ClientHello → extract_sni() → Hand off to Multiplexer
  Interception methods (Windows):
    - WinDivert: packet-level NAT rewrite (captures ALL apps)
    - System proxy: registry-based (apps may ignore)
    - Auto: try WinDivert first, fall back to system proxy

Both modes share:
Multiplexer → NEW_CONNECTION + DATA frames → TLS Tunnel → Proxy Server

TunnelClient → TLS → ProxyServer TunnelPort
  ├── AUTH "machineId:token" → AUTH_OK
  └── Framed<TlsStream, FrameCodec> → split into read/write halves

Multiplexer
  ├── Write loop: mpsc::Receiver<Frame> → SplitSink (tunnel write half)
  ├── Read loop: SplitStream (tunnel read half) → dispatch to connections
  └── Heartbeat loop: send HEARTBEAT, check for ACK timeout
```

## Project Structure

```
src/
  main.rs             # clap CLI: run, test, status, install, uninstall, service
  agent.rs            # Orchestrator: tunnel → proxy + health + transparent → event loop
  config.rs           # AgentConfig: serde YAML (+ TransparentConfig + InterceptionMethod)
  local_proxy.rs      # HTTP CONNECT proxy on localhost:19080
  transparent.rs      # Transparent TCP listener on 0.0.0.0:19443 (SNI-based)
  sni.rs              # TLS ClientHello SNI extraction (manual parser, no deps)
  health.rs           # Axum HTTP server on localhost:19876
  state.rs            # Install state persistence (JSON)
  lib.rs              # Public module exports
  tunnel/
    mod.rs            # Module declarations
    protocol.rs       # Binary frame codec
    client.rs         # TLS connect + AUTH handshake + reconnect
    multiplexer.rs    # Connection ID map, bidirectional bridges, heartbeat
  platform/
    mod.rs            # PlatformOps trait + platform() factory
    windows.rs        # System proxy (registry), certutil, sc.exe service
    windivert.rs      # WinDivert packet interception (NAT rewrite for TCP:443)
    linux.rs          # iptables REDIRECT, ca-certificates, systemd service
tests/
  protocol_test.rs    # 25 tests: tunnel protocol
  sni_test.rs         # 11 tests: SNI parser
config/
  agent-config.example.yaml
```

## Key Patterns

### Binary Tunnel Protocol (`protocol.rs`)
Frame format: `[ConnID: 4B BE][Type: 1B][PayloadLen: 4B BE][Payload]`. Header = 9 bytes. Max payload = 65536 bytes. ConnID 0 = control channel.

`FrameCodec` implements `tokio_util::codec::{Decoder, Encoder}` for use with `Framed<T>`. This gives us automatic TCP fragmentation handling.

Frame types: NewConnection(0x01), Data(0x02), Close(0x03), Auth(0x04), AuthOk(0x05), AuthFail(0x06), Heartbeat(0x07), HeartbeatAck(0x08).

### SNI Parser (`sni.rs`)
Manual TLS ClientHello parser — no external dependencies. Walks the byte structure:
TLS record header → handshake type → skip version/random/session_id/ciphers/compression → parse extensions → find type 0x0000 → extract hostname.

Returns `SniError` enum for each failure mode (not TLS, not ClientHello, buffer too short, no SNI, invalid hostname).

### Transparent Listener (`transparent.rs`)
- Binds on `0.0.0.0:19443` (must be non-loopback for WinDivert/iptables REDIRECT)
- `stream.peek()` to read ClientHello without consuming bytes
- `extract_sni()` → hostname → `mux.new_connection(stream, hostname, 443)`
- Peeked bytes stay in kernel buffer — proxy server sees complete ClientHello for MITM

### WinDivert Interceptor (`platform/windivert.rs`)
Packet-level interception for Windows using WinDivert driver. Captures ALL outbound TCP:443 traffic regardless of app proxy settings.

- **Three WinDivert handles**: SOCKET (PID tracking, priority -1), outbound NETWORK (NAT rewrite), inbound NETWORK (reverse NAT)
- **Four OS threads**: socket tracker, outbound capture, inbound capture, NAT cleanup
- **PID exclusion**: SOCKET layer (without `sniff`) blocks connect() until recv(), guaranteeing PID is mapped before the SYN reaches the NETWORK handler. Excluded PIDs' packets pass through without NAT.
- **Auto-detection**: `agent.rs` finds the proxy server PID via `netstat -ano` on the tunnel port, plus always excludes the agent's own PID. This prevents redirect loops when the proxy runs on the same machine.
- **NAT table**: `DashMap<(src_ip, src_port), NatEntry>` with 5-minute TTL cleanup
- **Runtime lifecycle**: started/stopped by `agent.rs` when transparent mode is enabled (not at install time)
- **`WinDivertInterceptor`** struct with `start(transparent_port, tunnel_ip, excluded_pids)`, `stop()`, `is_running()` API

### Platform Abstraction (`platform/`)
`PlatformOps` trait with `platform()` factory. Compile-time gating via `#[cfg(target_os)]`.

**Windows**: Registry-based system proxy + certutil for CA certs + `sc.exe` for service management. `InternetSetOption` notification refreshes proxy settings. WinDivert available as alternative interception method (see `windivert.rs`).

**Linux**: iptables `-j REDIRECT` with `--uid-owner` exclusion (prevents loops) + `update-ca-certificates` + systemd unit file.

### Install State (`state.rs`)
JSON file at `%APPDATA%\Guardian\state.json` (Windows) or `~/.config/guardian/state.json` (Linux). Tracks what `install` changed so `uninstall` can cleanly reverse it.

### CLI (`main.rs`)
Subcommands: `run`, `test`, `status`, `install`, `uninstall`, `service {install,uninstall,start,stop,status}`.

`install` flow: check privileges → install CA cert → enable interception → optionally install service → save state.
`uninstall` flow: load state → disable interception → remove CA cert → remove service → delete state.

### Tunnel Client (`client.rs`)
- `connect_and_auth()`: TLS connect → send AUTH frame → await AUTH_OK (10s timeout)
- `connect_with_reconnect()`: exponential backoff loop (1s → 2s → 4s → ... → 60s max)
- Uses `webpki-roots` for system CA trust, or loads custom CA from config
- Returns `Framed<TlsStream<TcpStream>, FrameCodec>` for the multiplexer

### Multiplexer (`multiplexer.rs`)
- `Multiplexer::start(framed, shutdown)` → splits into read/write halves, spawns 3 tasks
- `new_connection(tcp_stream, host, port)` → assigns conn_id, sends NEW_CONNECTION, spawns bridge
- Bridge: local read → DATA frames (upload), channel rx → local write (download)
- DashMap for concurrent connection tracking
- Heartbeat: sends HEARTBEAT every 30s, errors if no ACK within 90s

### Local CONNECT Proxy (`local_proxy.rs`)
- Accepts TCP connections, parses `CONNECT host:port HTTP/1.1`
- Sends `200 Connection Established`, then reunites stream and hands to multiplexer
- Each connection runs in a spawned tokio task

### Health Endpoint (`health.rs`)
- Axum router on port 19876
- `GET /health` returns JSON: status, machine_id, tunnel uptime, active connections, last heartbeat

### Agent Lifecycle (`agent.rs`)
Startup: connect_with_reconnect → Multiplexer::start → spawn health server → spawn local proxy → conditionally spawn transparent listener → wait for Ctrl+C → shutdown

## Conventions

- **Rust 2021 edition**, Rust 1.75+ required
- **tokio** for async runtime (full features)
- **clap** for CLI (derive macros)
- **serde + serde_yaml** for config
- **tracing + tracing-subscriber** for structured logging
- **anyhow** for error handling in application code
- **thiserror** for typed errors in library code (protocol, sni)
- **DashMap** for concurrent maps (connection tracking)
- Platform ops use CLI tools (certutil, sc, reg, iptables, systemctl) — no heavy platform crate deps
- Config path: CLI `--config` flag → default `config/agent-config.yaml`
- Shutdown via `tokio::sync::watch` channel (cooperative cancellation)

## Known Decisions

- **No TLS certificate for local proxy**: The local proxy runs on localhost as plain HTTP. Only the tunnel to the server is encrypted.
- **Transparent listener on 0.0.0.0**: WinDivert/iptables cannot redirect to loopback; must bind on a real interface.
- **Manual SNI parser**: Zero new dependencies, ~170 lines. Avoids `tls-parser` + `nom` dependency chain.
- **Windows interception methods**: `InterceptionMethod` enum (`auto`, `windivert`, `system_proxy`) in config. Auto tries WinDivert first (captures all apps at packet level), falls back to system proxy (registry-based, works without driver signing). WinDivert runs as part of agent runtime, not at install time.
- **Linux uses iptables --uid-owner exclusion**: Prevents redirect loops by excluding the agent's own UID from the redirect rule.
- **CLI tools for platform ops**: Uses certutil/sc.exe/reg (Windows) and iptables/systemctl (Linux) instead of heavy platform crates.
- **Futures-util "sink" feature required**: `SinkExt::send()` on `Framed` needs `futures-util` with "sink" feature.
- **Connection IDs start at 1**: ID 0 is reserved for the control channel.
- **Patched windivert-sys**: `windivert-sys-patched/` is a local copy of windivert-sys 0.10.0 with its build script modified to `#define memcpy windivert_memcpy` and `#define memset windivert_memset` for the static build. Without this, WinDivert's custom `memcpy`/`memset` (designed for its `/NODEFAULTLIB` DLL build) leak into the host binary and cause infinite recursion (MSVC optimizes the byte-by-byte loop back into `call memcpy`). Referenced via `[patch.crates-io]` in Cargo.toml.
- **Static WinDivert linking**: Uses `windivert-sys` `static` feature (not `vendored`). The vendored DLL build uses debug flags (`/ZI`, `/JMC`, `/NODEFAULTLIB`) causing stack overflow. Static linking with CRT provides `__chkstk` for proper stack probing. Requires manual `WinDivertDllEntry` call for TLS initialization (see `windivert.rs`).
- **Sync/async command split**: `main.rs` handles install/uninstall/service commands synchronously in `run()` without creating a tokio runtime. Async commands go through `#[inline(never)] run_async_commands()` to prevent LLVM from merging the async future's stack frame into `run()`'s prologue.

## Future Work (not yet implemented)

- Phase 7: Hardening — crash safety, in-flight connection termination on tunnel loss, 502 when tunnel is down, resource limits
- macOS platform support (Network Extension / pf firewall)
