# Secret Proxy — Full Implementation Plan

## Overview

Build a **transparent secret-injecting proxy system** that intercepts outgoing HTTP/HTTPS requests from developer machines, scans headers for placeholder tokens (e.g. `__OPENAI_API_KEY__`), resolves them from a secure secret backend (AWS Secrets Manager), and forwards the request with real secret values injected. The secrets never exist on the client machine.

### Core Principle

Local development environments don't need real secrets. Only the 3rd-party APIs care about authentication. By routing traffic through a centralized proxy that injects secrets on-the-fly, we eliminate secret sprawl across machines, `.env` files, and LLM context windows.

### System Components

1. **Remote Proxy Server** (`proxy-server/`, Node.js + TypeScript) — MITM proxy that performs secret injection. Runs on a secure remote server.
2. **Local Agent** (`local-agent/`, Rust) — Lightweight daemon installed on each client machine (Linux + Windows). Transparently captures outbound traffic via OS-level packet interception and tunnels it to the remote proxy.
3. **Shared Protocol** — A binary tunnel framing protocol used for communication between the agent and proxy server. Each side implements it independently in its own language.

### Why Two Languages

- **Proxy server in Node/TS:** Best ecosystem for HTTP parsing, TLS manipulation, AWS SDK, streaming. Runs on one server — binary size and memory footprint don't matter. Developer productivity is highest here.
- **Local agent in Rust:** Needs low-level OS integration (iptables, WinDivert, `SO_ORIGINAL_DST`, cert stores), must be distributed as a zero-dependency static binary (~5-10MB), runs as a system daemon on every dev machine so must be lightweight (~2-5MB RAM), and has mature crates for all required functionality (`windivert`, `nix`, `tokio`, `rustls`).
- **Clean boundary:** The two components communicate exclusively via the binary tunnel protocol over a TLS connection. No shared code needed.

---

## Repository Structure

```
secret-proxy/
├── proxy-server/                        # Node.js + TypeScript
│   ├── src/
│   │   ├── index.ts                     # Entry point — starts proxy + tunnel listener
│   │   ├── proxy/
│   │   │   ├── server.ts                # HTTP/HTTPS forward proxy (CONNECT handler)
│   │   │   ├── mitm.ts                  # MITM TLS interception
│   │   │   ├── passthrough.ts           # Raw TCP passthrough for non-configured domains
│   │   │   └── cert-manager.ts          # Dynamic cert generation + caching
│   │   ├── tunnel/
│   │   │   ├── tunnel-server.ts         # Accepts authenticated tunnels from agents
│   │   │   └── session-manager.ts       # Tracks active agent sessions
│   │   ├── injection/
│   │   │   ├── scanner.ts               # Scans headers for __PLACEHOLDER__ patterns
│   │   │   └── injector.ts              # Domain validation + secret resolution + replacement
│   │   ├── secrets/
│   │   │   ├── types.ts                 # SecretProvider interface
│   │   │   ├── aws-provider.ts          # AWS Secrets Manager implementation
│   │   │   ├── env-provider.ts          # Env var provider (dev/testing)
│   │   │   └── cache.ts                 # In-memory TTL cache
│   │   ├── auth/
│   │   │   └── authenticator.ts         # Machine token validation
│   │   ├── audit/
│   │   │   └── audit-logger.ts          # Structured audit log
│   │   └── utils/
│   │       ├── logger.ts                # Pino logger setup
│   │       └── domain-matcher.ts        # Glob/regex domain matching
│   ├── config/
│   │   └── server-config.example.yaml
│   ├── certs/                           # Generated CA cert + key (gitignored)
│   ├── scripts/
│   │   └── generate-ca.ts              # Generate custom CA certificate + key
│   ├── tests/
│   │   ├── scanner.test.ts
│   │   ├── injector.test.ts
│   │   ├── cert-manager.test.ts
│   │   ├── domain-matcher.test.ts
│   │   ├── cache.test.ts
│   │   └── integration/
│   │       ├── proxy-e2e.test.ts
│   │       └── tunnel-e2e.test.ts
│   ├── Dockerfile
│   ├── package.json
│   ├── pnpm-lock.yaml
│   └── tsconfig.json
│
├── local-agent/                         # Rust
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                      # Entry point + CLI (clap)
│   │   ├── agent.rs                     # Main agent orchestrator
│   │   ├── tunnel/
│   │   │   ├── mod.rs
│   │   │   ├── client.rs                # Tunnel connection + auth + reconnect
│   │   │   ├── protocol.rs              # Tunnel framing protocol (encode/decode)
│   │   │   └── multiplexer.rs           # Multiplex many connections over one tunnel
│   │   ├── interceptor/
│   │   │   ├── mod.rs                   # Platform-agnostic trait
│   │   │   ├── linux/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── iptables.rs          # iptables/nftables rule management
│   │   │   │   ├── nftables.rs          # nftables alternative
│   │   │   │   └── transparent.rs       # SO_ORIGINAL_DST + SNI extraction
│   │   │   └── windows/
│   │   │       ├── mod.rs
│   │   │       ├── windivert.rs         # WinDivert packet interception + rewriting
│   │   │       ├── conn_track.rs        # Connection tracking (src_port → original_dest)
│   │   │       └── system_proxy.rs      # Fallback: registry-based system proxy
│   │   ├── cert/
│   │   │   ├── mod.rs                   # Platform-agnostic trait
│   │   │   ├── linux.rs                 # update-ca-certificates / update-ca-trust
│   │   │   └── windows.rs              # certutil -addstore
│   │   ├── service/
│   │   │   ├── mod.rs
│   │   │   ├── linux.rs                 # systemd unit generation + management
│   │   │   └── windows.rs              # Windows service (windows-service crate)
│   │   ├── health.rs                    # Health check HTTP endpoint
│   │   ├── config.rs                    # Agent config (serde + YAML)
│   │   └── sni.rs                       # TLS ClientHello SNI extraction
│   ├── config/
│   │   └── agent-config.example.yaml
│   ├── tests/
│   │   ├── tunnel_test.rs
│   │   ├── protocol_test.rs
│   │   └── sni_test.rs
│   ├── build.rs                         # Build script (embed WinDivert DLL on Windows)
│   └── Cross.toml                       # cross-compilation config
│
├── docs/
│   ├── architecture.md
│   ├── tunnel-protocol.md
│   └── security.md
│
└── README.md
```

---

## PART 1: REMOTE PROXY SERVER (Node.js + TypeScript)

### Tech Stack

- **Runtime:** Node.js 20+
- **Language:** TypeScript (strict mode)
- **Package manager:** pnpm
- **Build:** tsup
- **Dependencies:**
  - `node-forge` — dynamic TLS certificate generation
  - `@aws-sdk/client-secrets-manager` — AWS Secrets Manager
  - `yaml` — config parsing
  - `pino` — structured logging
  - `zod` — config validation
- **Testing:** vitest

---

### 1.1 Proxy Server (`proxy/server.ts`)

The main entry point for proxied connections.

**Behavior:**

1. Listen on a configurable port (default: `8080`) for direct proxy connections (local dev / fallback)
2. Also accept connections forwarded from the tunnel server (from remote agents)
3. Handle two request types:
   - **HTTP CONNECT** (HTTPS destinations): Client sends `CONNECT api.openai.com:443`
   - **Plain HTTP**: Standard forward proxy — read, scan, inject, forward
4. On CONNECT:
   - Authenticate the client (Proxy-Authorization header, or pre-authenticated via tunnel session)
   - Check if target domain is in the configured secret domain list
   - **If domain IS configured:** perform MITM → hand socket to `mitm.ts`
   - **If domain is NOT configured:** raw TCP passthrough → hand socket to `passthrough.ts`
   - Respond `200 Connection Established`, then hand off socket

**Implementation notes:**
- Use `http.createServer()` and listen for the `'connect'` event
- For tunnel-forwarded connections, the tunnel server passes the socket + metadata (original destination) directly to the proxy handler, skipping CONNECT parsing since the agent already resolved the destination
- Timeouts: 30s idle, 120s active transfer

### 1.2 MITM Module (`proxy/mitm.ts`)

TLS interception for configured domains.

**Flow:**

1. Receive raw client socket + target hostname
2. Get cert for hostname from cert-manager
3. Wrap client socket in `tls.TLSSocket` with the generated cert
4. Read decrypted HTTP request (method, URL, headers, body stream)
5. Pass headers through injection pipeline
6. Open real HTTPS connection to target, send modified request
7. Stream response back to client over TLS socket

**Implementation notes:**
- Parse HTTP/1.1 manually from the decrypted stream: read lines until `\r\n\r\n` for headers, handle body via `Content-Length` or `Transfer-Encoding: chunked`
- Support HTTP/1.1 keep-alive: after a response completes, loop back to read the next request on the same TLS connection
- Stream request bodies directly (we only scan headers, not body)
- Handle `Connection: close` properly
- Return 400 on malformed requests

### 1.3 Passthrough Module (`proxy/passthrough.ts`)

Zero-overhead TCP pipe for non-configured domains.

```ts
function passthrough(clientSocket: net.Socket, targetHost: string, targetPort: number): void {
  const targetSocket = net.connect(targetPort, targetHost);
  clientSocket.pipe(targetSocket);
  targetSocket.pipe(clientSocket);
  // Handle errors and cleanup on both sides
}
```

Most traffic (CDNs, package registries, etc.) flows through here. The proxy never decrypts it.

### 1.4 Certificate Manager (`proxy/cert-manager.ts`)

Dynamically generates TLS certificates signed by the custom CA.

**Behavior:**

1. On startup: load CA cert + key from disk (`certs/ca.crt`, `certs/ca.key`)
2. `getCertForHostname(hostname: string): { cert: Buffer, key: Buffer }`
3. First call for a hostname:
   - Generate RSA 2048-bit key pair
   - Create X.509 cert:
     - Subject CN = hostname
     - SAN (Subject Alternative Name) = hostname
     - Issuer = CA subject
     - Serial = random
     - Validity = 1 year
     - `basicConstraints: cA = false`
     - Signed with CA private key (SHA-256)
   - Cache in `Map<string, { cert, key, createdAt }>`
4. Subsequent calls: return from cache
5. Optional: generate wildcard certs (e.g. `*.openai.com` for `api.openai.com`) to reduce cache entries

**Use `node-forge` for cert generation.**

### 1.5 Tunnel Server (`tunnel/tunnel-server.ts`)

Accepts persistent authenticated tunnels from agents.

**Behavior:**

1. Listen on a separate port (default: `8443`) over TLS
2. On agent connection:
   a. TLS handshake (using the proxy's real TLS cert — NOT the custom CA)
   b. Read AUTH frame (machine ID + token)
   c. Validate against config
   d. If valid: register session, begin accepting forwarded connections
   e. If invalid: send AUTH_FAIL, close
3. Multiplexed connection forwarding using the tunnel protocol (see below)
4. For each NEW_CONNECTION frame: extract original destination, create a virtual socket, pass to proxy handler
5. Send/receive HEARTBEAT every 30s
6. On tunnel disconnect: close all associated forwarded connections

**The tunnel uses a real TLS certificate** for the proxy server's domain (e.g. `proxy.mycompany.com`), not the custom CA. The custom CA is only for MITM-ing target API domains.

### 1.6 Session Manager (`tunnel/session-manager.ts`)

Tracks active agent sessions.

```ts
interface AgentSession {
  machineId: string;
  connectedAt: Date;
  socket: tls.TLSSocket;
  activeConnections: Map<number, VirtualSocket>;
}

class SessionManager {
  registerSession(machineId: string, socket: tls.TLSSocket): void;
  removeSession(machineId: string): void;
  getSession(machineId: string): AgentSession | undefined;
  getAllSessions(): AgentSession[];
}
```

### 1.7 Placeholder Scanner (`injection/scanner.ts`)

Pure function that finds placeholder tokens in HTTP header values.

```ts
interface PlaceholderMatch {
  headerName: string;       // e.g. "Authorization"
  placeholder: string;      // e.g. "__OPENAI_API_KEY__"
  secretName: string;       // e.g. "OPENAI_API_KEY"
}

interface ScanResult {
  matches: PlaceholderMatch[];
  warnings: string[];
}

function scanHeaders(headers: Record<string, string>): ScanResult;
```

**Pattern:** `/__([A-Z][A-Z0-9_]{1,63})__/g`

**Warning detection** for near-misses:
- Single underscores: `_NAME_` → `"Possible malformed placeholder: '_NAME_'. Did you mean '__NAME__'?"`
- Lowercase: `__name__` → `"Lowercase placeholder: '__name__'. Placeholders must be UPPERCASE."`
- Spaces: `__OPEN AI__` → `"Placeholder contains spaces."`

Warnings are logged but don't block the request.

### 1.8 Injector (`injection/injector.ts`)

Orchestrates the injection pipeline.

```ts
interface InjectionResult {
  modifiedHeaders: Record<string, string>;
  injections: Array<{ headerName: string; secretName: string }>;
  warnings: string[];
  errors: string[];
}

async function injectSecrets(
  targetDomain: string,
  headers: Record<string, string>,
  config: ProxyConfig,
  secretResolver: SecretResolver,
): Promise<InjectionResult>;
```

**Flow:**
1. `scanHeaders()` to find placeholders
2. For each match:
   a. Look up secret name in config
   b. Verify secret is mapped to this target domain
   c. **Valid:** resolve via `secretResolver`, replace in header value
   d. **Secret not found:** log error, leave placeholder as-is
   e. **Secret exists but wrong domain:** log warning (possible exfiltration), do NOT inject
3. Return modified headers + audit trail

### 1.9 Secret Providers (`secrets/`)

**Interface:**
```ts
interface SecretProvider {
  name: string;
  getSecret(path: string): Promise<string>;
}
```

**AWS Secrets Manager provider (`aws-provider.ts`):**
- `@aws-sdk/client-secrets-manager`
- `GetSecretValueCommand({ SecretId: path })` → returns `SecretString`
- Region configurable
- Credentials from standard AWS chain

**Env provider (`env-provider.ts`):**
- `getSecret(path)` → `process.env[path]`
- For local development and testing without AWS

**Cache (`cache.ts`):**
```ts
class SecretCache {
  private store: Map<string, { value: string; expiresAt: number }>;
  get(key: string): string | undefined;
  set(key: string, value: string, ttlMs: number): void;
  invalidate(key: string): void;
  clear(): void;
}
```
Default TTL: 300 seconds.

**Secret Resolver** (wraps cache + provider):
```ts
class SecretResolver {
  constructor(providers: Map<string, SecretProvider>, cache: SecretCache, defaultTtl: number);
  async getSecret(secretConfig: SecretConfig): Promise<string>;
  // cache check → miss → provider call → cache store → return
}
```

### 1.10 Authenticator (`auth/authenticator.ts`)

- Direct proxy connections: extract `Proxy-Authorization: Basic base64(machineId:token)`
- Tunnel connections: pre-authenticated at tunnel handshake
- Validate against config machine list
- Return machine ID on success, 407 on failure
- Auth can be disabled in config for local dev

### 1.11 Audit Logger (`audit/audit-logger.ts`)

```ts
interface AuditEntry {
  timestamp: string;
  machineId: string;
  targetDomain: string;
  requestMethod: string;
  requestPath: string;
  placeholdersFound: string[];
  placeholdersInjected: string[];
  placeholdersRejected: string[];
  warnings: string[];
}
```

- JSON lines format to a dedicated audit log file
- **NEVER log secret values**
- Daily file rotation, configurable retention

### 1.12 Domain Matcher (`utils/domain-matcher.ts`)

```ts
function matchesDomain(hostname: string, pattern: string): boolean;
```

- Exact: `"api.openai.com"` matches `api.openai.com`
- Wildcard: `"*.stripe.com"` matches `checkout.stripe.com`, `api.stripe.com`
- Wildcard does NOT match bare: `"*.stripe.com"` does NOT match `stripe.com`
- Case-insensitive
- IP glob: `"10.*"` matches `10.0.0.1`
- CIDR: `"10.0.0.0/8"` for bypass lists

### 1.13 CA Generation Script (`scripts/generate-ca.ts`)

Run once:
```bash
pnpm run generate-ca
```

- `node-forge`: self-signed CA, RSA 4096-bit, validity 10 years
- `basicConstraints: { cA: true }`
- Outputs `certs/ca.crt` (public, distributed to agents) and `certs/ca.key` (private, stays on server)

---

## PART 2: LOCAL AGENT (Rust)

### Tech Stack

- **Language:** Rust (2021 edition)
- **Async runtime:** tokio (full features)
- **Key crates:**
  - `tokio` — async runtime, TCP, IO
  - `tokio-rustls` / `rustls` — TLS for the tunnel connection
  - `clap` — CLI argument parsing
  - `serde` + `serde_yaml` — config deserialization
  - `tracing` + `tracing-subscriber` — structured logging
  - `nix` (Linux) — `getsockopt(SO_ORIGINAL_DST)`, process UID
  - `windivert` (Windows) — packet interception via WinDivert
  - `windows-service` (Windows) — Windows service integration
  - `axum` or `hyper` — tiny HTTP server for health endpoint
  - `bytes` — efficient byte buffer handling for tunnel protocol
  - `dashmap` — concurrent hash map for connection tracking (Windows)

### Build & Distribution

- **Linux:** `cargo build --release --target x86_64-unknown-linux-musl` → single static binary (~5-10MB)
- **Windows:** `cargo build --release --target x86_64-pc-windows-msvc` → `.exe` (~5-10MB)
- **Cross-compilation:** use `cross` tool to build Windows binary from Linux or vice versa
- **WinDivert bundling:** `build.rs` embeds or expects `WinDivert.dll` + `WinDivert64.sys` alongside the exe

---

### 2.1 CLI (`main.rs`)

```
secret-proxy-agent install     # Install service + CA cert + interception rules
secret-proxy-agent uninstall   # Remove everything cleanly
secret-proxy-agent start       # Start the service
secret-proxy-agent stop        # Stop the service
secret-proxy-agent restart     # Restart the service
secret-proxy-agent status      # Show connection status, tunnel uptime, active connections
secret-proxy-agent run         # Run in foreground (used by service manager)
secret-proxy-agent test        # Send a test request through proxy, verify injection
secret-proxy-agent logs        # Tail agent logs
```

Use `clap` derive macros for argument parsing.

**`install` command flow:**
1. Check for admin/root privileges
2. Prompt for or read config: proxy server URL, machine token
3. Download / copy CA certificate
4. Install CA cert into OS trust store (platform-specific)
5. Write agent config to platform-appropriate location:
   - Linux: `/etc/secret-proxy/agent-config.yaml`
   - Windows: `C:\ProgramData\SecretProxy\agent-config.yaml`
6. Install as system service (systemd / Windows Service)
7. Start the service
8. Run self-test to verify connectivity

**`uninstall` command flow:**
1. Stop the service
2. Remove traffic interception rules
3. Remove CA cert from trust store
4. Remove system service
5. Remove config files

### 2.2 Agent Orchestrator (`agent.rs`)

The main daemon logic, invoked by the `run` subcommand.

**Startup sequence:**
1. Load config from `agent-config.yaml`
2. Verify CA cert is installed (warn if not)
3. **Clean up stale interception rules from a previous crash** (critical for crash safety)
4. Start the local transparent proxy listener (platform-specific)
5. Set up OS-level traffic interception rules
6. Establish tunnel to remote proxy server
7. Start health check HTTP endpoint
8. Enter tokio event loop

**Shutdown sequence (on SIGTERM / service stop):**
1. **Remove traffic interception rules FIRST** (before anything else)
2. Close all active forwarded connections
3. Close tunnel
4. Exit

**Crash safety:**
- Startup step 3 always cleans up stale rules — handles previous crash
- Linux: flush `SECRET_PROXY` iptables chain if it exists
- Windows: WinDivert handles auto-release on process exit, but agent still checks for stale state

### 2.3 Tunnel Client (`tunnel/client.rs`)

Persistent authenticated multiplexed tunnel to the remote proxy.

**Flow:**
1. Connect to proxy server tunnel port over TLS (`tokio-rustls`)
2. Verify server TLS certificate (standard validation, real cert)
3. Send AUTH frame (machine ID + token)
4. Wait for AUTH_OK
5. Multiplexing mode:
   - Intercepted connections → NEW_CONNECTION + DATA frames
   - Incoming DATA frames → forward to local socket
   - CLOSE frames → close local socket
6. HEARTBEAT every 30s, timeout after 60s

**Reconnection:**
- Exponential backoff: 1s → 2s → 4s → ... → 60s max
- Reset on successful auth
- All in-flight connections terminated on tunnel loss

### 2.4 Tunnel Protocol (`tunnel/protocol.rs`)

Binary framing protocol. Both Rust agent and Node.js server implement this identically.

```
Frame layout:
┌──────────────┬──────────────┬───────────────────┬──────────────┐
│ Connection ID │ Frame Type   │ Payload Length     │ Payload      │
│ (4 bytes, BE) │ (1 byte)     │ (4 bytes, BE)      │ (variable)   │
└──────────────┴──────────────┴───────────────────┴──────────────┘

Frame Types:
  0x01 = NEW_CONNECTION     payload: JSON { "host": "api.openai.com", "port": 443 }
  0x02 = DATA               payload: raw bytes
  0x03 = CLOSE              payload: empty (0 length)
  0x04 = AUTH               payload: JSON { "machine_id": "...", "token": "..." }
  0x05 = AUTH_OK             payload: empty
  0x06 = AUTH_FAIL           payload: JSON { "reason": "..." }
  0x07 = HEARTBEAT           payload: empty
  0x08 = HEARTBEAT_ACK       payload: empty

Connection ID:
  - 0 = control channel (AUTH, HEARTBEAT)
  - 1+ = forwarded connections (assigned by agent, incrementing)

Byte order: big-endian (network order) for all multi-byte integers.
Max payload size: 65536 bytes (fragment larger data).
```

**Rust implementation:** `bytes::BytesMut` for zero-copy parsing, `tokio::io::AsyncRead`/`AsyncWrite`.

**Node.js implementation:** `Buffer` with manual offset tracking on `'data'` events. Handle partial frame reads (TCP can split frames across packets).

### 2.5 Multiplexer (`tunnel/multiplexer.rs`)

Manages multiple logical connections over the single tunnel.

```rust
struct Multiplexer {
    tunnel: TlsStream<TcpStream>,
    connections: HashMap<u32, ConnectionHandle>,
    next_conn_id: AtomicU32,
}

struct ConnectionHandle {
    local_socket: TcpStream,
    original_dest: SocketAddr,
    hostname: String,
}
```

Use `tokio::select!` to concurrently:
- Read frames from tunnel → dispatch DATA to the right local socket
- Read from each local socket → send DATA frames to tunnel
- Send periodic HEARTBEATs
- Detect dead connections and send CLOSE

---

### 2.6 Linux Interceptor (`interceptor/linux/`)

#### 2.6.1 iptables Manager (`iptables.rs`)

**Rules to install:**
```bash
# Create a dedicated chain for clean management
iptables -t nat -N SECRET_PROXY

# CRITICAL: bypass proxy server IP (prevent routing loops!)
iptables -t nat -A SECRET_PROXY -d <PROXY_SERVER_IP> -j RETURN

# CRITICAL: bypass agent's own traffic (prevent routing loops!)
iptables -t nat -A SECRET_PROXY -m owner --uid-owner secret-proxy -j RETURN

# Bypass private/local ranges
iptables -t nat -A SECRET_PROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A SECRET_PROXY -d 10.0.0.0/8 -j RETURN
iptables -t nat -A SECRET_PROXY -d 172.16.0.0/12 -j RETURN
iptables -t nat -A SECRET_PROXY -d 192.168.0.0/16 -j RETURN
# ... additional bypass IPs from config

# Redirect HTTP/HTTPS to local transparent proxy
iptables -t nat -A SECRET_PROXY -p tcp --dport 80 -j REDIRECT --to-port 19080
iptables -t nat -A SECRET_PROXY -p tcp --dport 443 -j REDIRECT --to-port 19443

# Attach to OUTPUT chain
iptables -t nat -A OUTPUT -p tcp -j SECRET_PROXY
```

**Implementation:**
- Execute via `std::process::Command`
- Named chain for clean install/uninstall (flush + delete)
- Always flush on startup before re-adding (idempotent, crash recovery)
- Detect `nft` binary availability → prefer nftables on newer systems
- The `--uid-owner` rule prevents the agent's tunnel traffic from being intercepted (loop prevention)

#### 2.6.2 nftables Manager (`nftables.rs`)

Equivalent nftables ruleset:
```
table ip secret_proxy {
  chain output {
    type nat hook output priority -100; policy accept;
    ip daddr <PROXY_IP> accept
    meta skuid secret-proxy accept
    ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
    tcp dport 80 redirect to :19080
    tcp dport 443 redirect to :19443
  }
}
```

#### 2.6.3 Transparent Proxy (`transparent.rs`)

Listens on redirected ports, recovers original destination, extracts SNI.

**Flow:**
1. `TcpListener::bind("0.0.0.0:19443")` (HTTPS), `:19080` (HTTP)
2. On new connection: `getsockopt(SO_ORIGINAL_DST)` via the `nix` crate → original dest IP + port
3. HTTPS: peek at TLS ClientHello → extract SNI hostname (see `sni.rs`)
4. HTTP: parse `Host` header
5. Pass connection + dest info to multiplexer for tunneling

**SO_ORIGINAL_DST in Rust:**
```rust
use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
use std::os::unix::io::AsRawFd;

let orig_dst = getsockopt(stream.as_raw_fd(), OriginalDst)?;
// Returns sockaddr_in with original IP + port
```

---

### 2.7 Windows Interceptor (`interceptor/windows/`)

#### 2.7.1 WinDivert Interceptor (`windivert.rs`)

Kernel-level packet interception using WinDivert.

**Flow:**

1. Open WinDivert handle with filter:
   ```
   outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)
   and ip.DstAddr != <PROXY_SERVER_IP>
   and ip.DstAddr != 127.0.0.1
   ```
2. For each intercepted outbound SYN packet (new TCP connection):
   a. Extract original destination IP + port from IP/TCP headers
   b. Store mapping in connection tracker: `(src_ip, src_port) → (orig_dst_ip, orig_dst_port)`
   c. Rewrite destination to `127.0.0.1:<local_proxy_port>`
   d. Recalculate IP + TCP checksums (WinDivert provides helpers)
   e. Re-inject the modified packet
3. For subsequent packets of tracked connections:
   a. **Outbound:** rewrite dst to `127.0.0.1:<local_proxy_port>`, fix checksums, re-inject
   b. **Inbound (responses):** rewrite src from `127.0.0.1` back to the original dest IP, fix checksums, re-inject — so the client TCP stack sees responses from the expected IP
4. On FIN/RST: clean up connection tracking entry

**Using the `windivert` Rust crate:**
```rust
use windivert::prelude::*;

let wd = WinDivert::network(
    "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)",
    0,  // priority
    0,  // flags
)?;

loop {
    let packet = wd.recv()?;
    // Parse IP + TCP headers from packet.data
    // Modify destination, recalculate checksums
    wd.send(&modified_packet)?;
}
```

**Implementation notes:**
- Run WinDivert recv/send loop on a dedicated `std::thread` (blocking I/O, not async)
- Bridge to tokio via `tokio::sync::mpsc` channels
- WinDivert DLL + SYS driver files bundled alongside the agent exe
- Requires administrator privileges
- WinDivert driver is signed — Windows loads it without issues

#### 2.7.2 Connection Tracker (`conn_track.rs`)

Tracks original destinations for WinDivert-rewritten connections.

```rust
struct ConnTracker {
    // Key: (source IP, source port) → Value: (original dest IP, original dest port)
    map: DashMap<(Ipv4Addr, u16), (Ipv4Addr, u16)>,
}

impl ConnTracker {
    fn track(&self, src_ip: Ipv4Addr, src_port: u16, orig_dst: (Ipv4Addr, u16));
    fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<(Ipv4Addr, u16)>;
    fn remove(&self, src_ip: Ipv4Addr, src_port: u16);
    fn cleanup_stale(&self, max_age: Duration);  // Run every 60s, remove entries > 5min old
}
```

- `DashMap` for concurrent access (WinDivert thread + proxy listener thread)
- Periodic cleanup of stale entries
- Clean up on FIN/RST packets

#### 2.7.3 Windows Transparent Proxy Listener

Same role as Linux transparent proxy but uses connection tracker for original dest:

```rust
let peer = stream.peer_addr()?;
let original_dest = conn_tracker.lookup(peer.ip(), peer.port());
// Then extract SNI from ClientHello (same as Linux) and forward to tunnel
```

#### 2.7.4 System Proxy Fallback (`system_proxy.rs`)

Simpler alternative — set system-wide proxy via Windows Registry:

```rust
use winreg::RegKey;

fn enable_system_proxy(proxy_addr: &str, bypass: &str) -> Result<()> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let settings = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        winreg::enums::KEY_SET_VALUE,
    )?;
    settings.set_value("ProxyEnable", &1u32)?;
    settings.set_value("ProxyServer", proxy_addr)?;
    settings.set_value("ProxyOverride", bypass)?;
    Ok(())
}
```

Also set `HTTP_PROXY`/`HTTPS_PROXY` env vars system-wide via registry.

Covers ~90% of apps. Offered as fallback during `install` if WinDivert has issues. The CLI `install` asks interception mode: `windivert` (default on Windows) or `system-proxy` (fallback).

---

### 2.8 SNI Extraction (`sni.rs`)

Extract hostname from TLS ClientHello without decrypting.

```rust
/// Peek at first bytes of a TLS connection, extract SNI hostname.
/// Returns None if no SNI extension found.
fn extract_sni(buf: &[u8]) -> Option<String>;
```

Parse:
1. TLS record header (5 bytes): content type `0x16` (Handshake), version, length
2. Handshake header: type `0x01` (ClientHello), length
3. Skip to extensions list
4. Iterate extensions until `type == 0x0000` (server_name)
5. Extract hostname string from ServerNameList

~50-80 lines. Can also use `tls-parser` crate.

**Important:** Use `TcpStream::peek()` to read without consuming — the full ClientHello must still be forwarded through the tunnel.

---

### 2.9 CA Certificate Management (`cert/`)

#### Linux (`cert/linux.rs`)

```rust
fn install_ca(cert_path: &Path) -> Result<()> {
    if Path::new("/usr/local/share/ca-certificates").exists() {
        // Debian/Ubuntu
        fs::copy(cert_path, "/usr/local/share/ca-certificates/secret-proxy-ca.crt")?;
        Command::new("update-ca-certificates").status()?;
    } else if Path::new("/etc/pki/ca-trust/source/anchors").exists() {
        // RHEL/CentOS/Fedora
        fs::copy(cert_path, "/etc/pki/ca-trust/source/anchors/secret-proxy-ca.crt")?;
        Command::new("update-ca-trust").status()?;
    }
    Ok(())
}
```

**Known limitation:** Java and Firefox have their own trust stores — document manual steps.

#### Windows (`cert/windows.rs`)

```rust
fn install_ca(cert_path: &Path) -> Result<()> {
    Command::new("certutil")
        .args(["-addstore", "-f", "ROOT", cert_path.to_str().unwrap()])
        .status()?;
    Ok(())
}
```

Requires admin. Covers Chrome, Edge, curl, most HTTP libs. Firefox has its own store (document as limitation).

---

### 2.10 Service Management (`service/`)

#### Linux (`service/linux.rs`)

Generate systemd unit:
```ini
[Unit]
Description=Secret Proxy Local Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/secret-proxy-agent run
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Interception rules are managed by the `run` command (setup on start, teardown on stop/crash via shutdown handler).

#### Windows (`service/windows.rs`)

Use `windows-service` crate for native Windows service integration. Runs as `LocalSystem`.

---

### 2.11 Health Endpoint (`health.rs`)

Tiny HTTP server on `localhost:19876`:

```json
GET /health → 200 OK
{
  "status": "connected",
  "tunnel_uptime_seconds": 3600,
  "active_connections": 5,
  "last_heartbeat": "2025-01-15T10:30:00Z",
  "interception_mode": "iptables",
  "machine_id": "dev-laptop-1"
}
```

---

## PART 3: CONFIGURATION

### Server Config (`proxy-server/config/server-config.example.yaml`)

```yaml
proxy:
  port: 8080
  host: "0.0.0.0"

tunnel:
  port: 8443
  tls:
    cert: "/etc/secret-proxy/server.crt"
    key: "/etc/secret-proxy/server.key"

ca:
  cert: "certs/ca.crt"
  key: "certs/ca.key"

secrets:
  - name: OPENAI_API_KEY
    source: aws-secrets-manager
    path: /prod/openai/api-key
    domains:
      - "api.openai.com"

  - name: STRIPE_SECRET_KEY
    source: aws-secrets-manager
    path: /prod/stripe/secret-key
    domains:
      - "*.stripe.com"

  - name: GITHUB_TOKEN
    source: env
    path: GITHUB_TOKEN
    domains:
      - "api.github.com"
      - "*.githubusercontent.com"

  - name: ANTHROPIC_API_KEY
    source: aws-secrets-manager
    path: /prod/anthropic/api-key
    domains:
      - "api.anthropic.com"

cache:
  ttl_seconds: 300

auth:
  machines:
    - id: dev-laptop-1
      token: "long-random-token-1"
    - id: dev-laptop-2
      token: "long-random-token-2"
    - id: prod-vps-1
      token: "long-random-token-3"

bypass:
  - "localhost"
  - "127.0.0.1"
  - "10.*"
  - "172.16.*"
  - "192.168.*"
  - "*.internal.company.com"

aws:
  region: us-east-1

logging:
  level: info
  audit:
    enabled: true
    path: "/var/log/secret-proxy/audit.log"
    retention_days: 90
```

### Agent Config (`local-agent/config/agent-config.example.yaml`)

```yaml
server:
  host: "proxy.mycompany.com"
  tunnel_port: 8443

auth:
  machine_id: "dev-laptop-1"
  token: "long-random-token-1"

ca_cert_path: "/etc/secret-proxy/ca.crt"

interception:
  mode: "transparent"              # Linux: transparent | Windows: windivert | system-proxy
  local_https_port: 19443
  local_http_port: 19080

bypass:
  domains:
    - "localhost"
    - "*.internal.company.com"
  ips:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

health:
  port: 19876

logging:
  level: info
  path: "/var/log/secret-proxy/agent.log"

reconnect:
  initial_delay_ms: 1000
  max_delay_ms: 60000
  backoff_multiplier: 2
```

### Config Validation

**Proxy server (TypeScript):** Zod schemas with clear error messages.

**Agent (Rust):** `serde` deserialization with `#[serde(default)]` + custom validation functions.

---

## PART 4: THE FULL REQUEST FLOW

### With Local Agent (Production)

```
1. Developer runs:
   curl https://api.openai.com/v1/models \
     -H "Authorization: Bearer __OPENAI_API_KEY__"
   (No proxy env vars needed — traffic is intercepted transparently)

2. OS intercepts outbound TCP SYN to api.openai.com:443
   Linux: iptables REDIRECT → 127.0.0.1:19443
   Windows: WinDivert rewrites dst → 127.0.0.1:19443

3. Agent's transparent proxy listener accepts the connection
   - Linux: getsockopt(SO_ORIGINAL_DST) → 104.18.6.192:443
   - Windows: conn_tracker.lookup(src_port) → 104.18.6.192:443
   - Peek at TLS ClientHello → SNI = "api.openai.com"

4. Agent sends through tunnel to remote proxy:
   → NEW_CONNECTION { host: "api.openai.com", port: 443 }
   → DATA frames (raw TCP bytes from curl)

5. Remote proxy receives the tunneled connection
   - "api.openai.com" is in secret config → MITM mode
   - TLS handshake with curl using dynamic cert for api.openai.com
     (signed by custom CA, trusted because CA is in OS store)

6. Proxy reads decrypted HTTP request:
   GET /v1/models HTTP/1.1
   Host: api.openai.com
   Authorization: Bearer __OPENAI_API_KEY__

7. Scanner finds __OPENAI_API_KEY__ in Authorization header
   Injector: OPENAI_API_KEY is mapped to api.openai.com ✓
   Resolver: fetches from AWS Secrets Manager (or cache) → "sk-proj-abc123..."
   Replaces: Authorization: Bearer sk-proj-abc123...

8. Proxy makes REAL HTTPS request to api.openai.com:
   GET /v1/models HTTP/1.1
   Authorization: Bearer sk-proj-abc123...

9. OpenAI responds 200 OK

10. Response streams back: OpenAI → proxy → tunnel → agent → curl
```

### Direct Proxy Mode (Local Dev / Testing)

```
HTTPS_PROXY=http://machine-id:token@localhost:8080 \
  curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"

Steps 5-10 same. Steps 1-4 replaced by curl's native HTTPS_PROXY support.
```

---

## PART 5: TESTING

### Unit Tests — Proxy Server (vitest)
- `scanner.test.ts` — pattern matching, edge cases, warning detection
- `domain-matcher.test.ts` — exact, wildcard, CIDR, case
- `injector.test.ts` — mock resolver, domain binding, multi-placeholder, exfiltration rejection
- `cert-manager.test.ts` — generation, SAN, caching
- `cache.test.ts` — TTL expiry, hits/misses

### Unit Tests — Agent (cargo test)
- `protocol_test.rs` — frame encode/decode, partial reads, max payload
- `sni_test.rs` — SNI extraction from real ClientHello bytes
- `conn_track_test.rs` (Windows) — concurrent tracking, cleanup

### Integration Tests — Proxy Server
- `proxy-e2e.test.ts`:
  1. Start mock HTTPS target that echoes headers
  2. Start proxy with env provider + test config
  3. HTTPS request through proxy with placeholder
  4. Assert mock received real secret
  5. Assert wrong-domain placeholder NOT injected

- `tunnel-e2e.test.ts`:
  1. Start proxy with tunnel listener
  2. Mock tunnel client speaking the framing protocol
  3. Send NEW_CONNECTION + DATA with placeholder request
  4. Assert injection + response forwarding

### End-to-End (Full System)
- Proxy server in one container, agent in another
- curl from agent container with placeholder header
- Verify target received real secret
- Verify audit log recorded injection

---

## PART 6: SECURITY CONSIDERATIONS

1. **CA private key** — most critical asset. Only on proxy server. Never on clients, never in version control. Production: consider AWS KMS / HSM for signing.

2. **Proxy sees decrypted traffic for configured domains.** Harden: minimal services, disk encryption, restricted access.

3. **Never log secret values.** Not in any level, errors, or crash dumps. Log names and domains only.

4. **Domain-secret binding prevents exfiltration.** `__OPENAI_API_KEY__` in a request to `evil.com` → NOT injected.

5. **Machine tokens:** 32+ bytes random. Rotate periodically.

6. **Tunnel encryption:** TLS with real (not self-signed) cert on proxy.

7. **Loop prevention (Linux):** iptables bypass for proxy server IP AND `--uid-owner` bypass for agent process.

8. **Loop prevention (Windows):** WinDivert filter excludes proxy server IP.

9. **Crash safety:** If agent crashes with iptables rules active, ports 80/443 break. Mitigations:
   - Always clean stale rules on startup
   - systemd `Restart=always` + `RestartSec=5`
   - Consider watchdog script as extra safety net

10. **No secrets on clients.** Secrets exist only in proxy server memory + secrets backend.

11. **Rate limiting** per machine token on the proxy.

---

## PART 7: DEPLOYMENT

### Proxy Server

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build
EXPOSE 8080 8443
CMD ["node", "dist/index.js"]
```

Needs:
- Inbound: 8443 (tunnel) to agent IPs, optionally 8080 (direct proxy)
- Outbound: target API domains + AWS Secrets Manager
- TLS cert for proxy domain (Let's Encrypt / ACM)
- AWS IAM credentials for Secrets Manager
- CA cert + key in `certs/`

### Agent Distribution

```bash
# Linux
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/secret-proxy-agent

# Windows
cargo build --release --target x86_64-pc-windows-msvc
# → target/x86_64-pc-windows-msvc/release/secret-proxy-agent.exe
```

Distribute:
- **Linux:** `.tar.gz` with binary + example config + CA cert
- **Windows:** `.zip` with exe + WinDivert DLLs + example config + CA cert

Install:
```bash
# Linux
sudo ./secret-proxy-agent install

# Windows (admin PowerShell)
.\secret-proxy-agent.exe install
```

---

## PART 8: FUTURE ENHANCEMENTS (Not In Scope)

- Web management UI (secrets, machines, audit logs)
- Per-machine secret ACLs
- Rule engine (conditional injection)
- Secret rotation via AWS EventBridge
- mTLS for tunnel (agent client certs)
- Prometheus metrics + Grafana dashboard
- Multi-proxy HA (load balancer + Redis shared cache)
- Request body scanning
- WebSocket / gRPC header injection
