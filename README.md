# Guardian

Transparent secret injection for HTTPS traffic. Applications use `__PLACEHOLDER__` tokens instead of real API keys, and Guardian intercepts the traffic, resolves the real secrets from configured providers (environment variables, AWS Secrets Manager), and injects them before the request reaches the target API. Secrets never exist on developer machines.

## Architecture

```
Developer Machine                          Server
┌──────────────────────────┐              ┌─────────────────────────────┐
│  Your App                │              │  Guardian Proxy Server      │
│  "Bearer __OPENAI_KEY__" │              │                             │
│         │                │  TLS tunnel  │  MITM → Scan headers        │
│  ┌──────┴──────┐         │◄────────────►│  → Resolve secrets          │
│  │ Mode A:     │         │  binary      │  → Inject real values       │
│  │ HTTPS_PROXY │         │  framing     │  → Forward to target API    │
│  │ (port 19080)│         │              │                             │
│  ├─────────────┤         │              │                             │
│  │ Mode B:     │         │              │                             │
│  │ Transparent │         │              │                             │
│  │ (port 19443)│         │              │                             │
│  └─────────────┘         │              │                             │
│  Local Agent (Rust)      │              │                             │
└──────────────────────────┘              └─────────────────────────────┘
```

Guardian has two components:

| Component | Language | Purpose |
|-----------|----------|---------|
| **[proxy-server/](proxy-server/)** | Node.js/TypeScript | Central proxy that holds secrets, performs MITM TLS interception, and injects real values into requests |
| **[local-agent/](local-agent/)** | Rust | Lightweight daemon on developer machines that tunnels traffic to the proxy server |

## How It Works

Guardian supports two interception modes:

### Mode A: Explicit Proxy (default)

Applications set `HTTPS_PROXY=http://127.0.0.1:19080` and the agent's CONNECT proxy handles the rest. Simple, works everywhere, no admin privileges needed.

### Mode B: Transparent Interception (zero-config)

The agent intercepts **all** outbound HTTPS traffic at the OS level — no per-app `HTTPS_PROXY` configuration needed. It extracts the target hostname from the TLS ClientHello (SNI), then routes through the tunnel. Requires a one-time `install` step with admin/root privileges.

Both modes share the same tunnel and proxy server — the only difference is how traffic enters the agent.

## Quick Start

### Prerequisites

- **Node.js 20+** and **pnpm** (for the proxy server)
- **Rust 1.75+** and **cargo** (for the local agent)
- **MSVC build tools** (Windows only — needed to compile the WinDivert driver library)

### 1. Set up the proxy server

```bash
cd proxy-server
pnpm install
pnpm run generate-ca
cp config/server-config.example.yaml config/server-config.yaml
# Edit config/server-config.yaml with your secrets and auth clients
```

To enable the tunnel server for remote agents, add a `tunnel` section to your config:

```yaml
tunnel:
  enabled: true
  port: 8443
  host: "0.0.0.0"
  tls:
    certFile: "certs/tunnel.crt"
    keyFile: "certs/tunnel.key"
  heartbeatIntervalMs: 30000
  heartbeatTimeoutMs: 90000
```

Set your secrets as environment variables, then start:

```bash
export OPENAI_API_KEY="sk-your-real-key"
pnpm run dev
```

### 2. Set up the local agent

```bash
cd local-agent
cargo build --release
cp config/agent-config.example.yaml config/agent-config.yaml
# Edit config/agent-config.yaml with your server address and auth credentials
```

Start the agent:

```bash
cargo run --release -- run --config config/agent-config.yaml
```

### 3. Use it

#### Option A: Explicit proxy (per-app)

```bash
# Point your app at the local agent's proxy
HTTPS_PROXY=http://127.0.0.1:19080 \
  curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"

# The proxy replaces __OPENAI_API_KEY__ with the real key
```

This works with any app that supports `HTTPS_PROXY` — curl, Python requests, Node.js fetch, etc.

#### Option B: Transparent interception (system-wide, no HTTPS_PROXY needed)

First, enable transparent mode in your agent config:

```yaml
transparent:
  enabled: true
  port: 19443        # default
  host: "0.0.0.0"   # default
  method: "auto"     # auto | windivert | system_proxy (Windows only)
```

On Windows, `method` controls how traffic is intercepted:
- **`auto`** (default): Tries WinDivert first (captures all apps at the packet level), falls back to system proxy if WinDivert is unavailable
- **`windivert`**: WinDivert only — fails if the driver can't load
- **`system_proxy`**: Registry-based system proxy only (works without driver signing, but apps that ignore the proxy setting won't be intercepted)

Then run the one-time install (requires admin/root):

```bash
# Windows: run as Administrator
# Linux: run with sudo

cargo run --release -- install \
  --config config/agent-config.yaml \
  --ca-cert ../proxy-server/certs/ca.crt
```

This does three things:
1. **Installs the CA certificate** into the system trust store (so apps trust the MITM proxy)
2. **Enables traffic interception** (Windows: system proxy; Linux: iptables REDIRECT rule)
3. Saves state so `uninstall` can cleanly reverse everything

Now start the agent and all HTTPS traffic is automatically intercepted:

```bash
cargo run --release -- run --config config/agent-config.yaml

# In another terminal — no HTTPS_PROXY needed!
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

To optionally install as a system service (auto-start on boot):

```bash
cargo run --release -- install \
  --config config/agent-config.yaml \
  --ca-cert ../proxy-server/certs/ca.crt \
  --service
```

#### Uninstalling

```bash
# Reverses all install actions: removes CA cert, disables interception, removes service
cargo run --release -- uninstall
```

### Local-only mode (no agent needed)

If you're running the proxy on the same machine, you can skip the agent entirely and point `HTTPS_PROXY` directly at the proxy server:

```bash
HTTPS_PROXY=http://machineId:token@127.0.0.1:8080 \
  curl --cacert proxy-server/certs/ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

## CLI Reference

```
guardian-agent <COMMAND>

Commands:
  run         Start the agent
  test        Test connectivity to tunnel server
  status      Show agent status via health endpoint
  install     Install Guardian (CA cert + interception + optional service)
  uninstall   Reverse all install actions
  service     Manage the system service (install/uninstall/start/stop/status)
```

### `run`

```bash
guardian-agent run [--config <path>]
```

Starts the agent: connects the tunnel, starts the CONNECT proxy (port 19080), optionally starts the transparent listener (port 19443 if `transparent.enabled: true`), and runs the health endpoint (port 19876).

### `install`

```bash
guardian-agent install --ca-cert <path> [--config <path>] [--no-cert] [--no-interception] [--service]
```

| Flag | Effect |
|------|--------|
| `--ca-cert <path>` | Path to the proxy server's CA certificate PEM file |
| `--no-cert` | Skip CA certificate installation |
| `--no-interception` | Skip enabling traffic interception |
| `--service` | Also install as a system service (auto-start on boot) |

### `uninstall`

```bash
guardian-agent uninstall [--force]
```

Reads the saved install state and reverses each action. Use `--force` if the state file is missing.

### `service`

```bash
guardian-agent service <install|uninstall|start|stop|status>
```

Manage the Guardian system service independently (Windows: `sc.exe`; Linux: systemd).

## Agent Configuration

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "path/to/server-ca.pem"   # optional: custom CA for tunnel TLS

auth:
  machine_id: "dev-machine-1"
  token: "secret-token"

local_proxy:
  host: "127.0.0.1"
  port: 19080

transparent:
  enabled: false      # set to true for transparent interception
  host: "0.0.0.0"    # must be non-loopback for OS-level redirect
  port: 19443
  method: "auto"      # Windows: auto | windivert | system_proxy

health:
  host: "127.0.0.1"
  port: 19876

reconnect:
  initial_delay_ms: 1000
  max_delay_ms: 60000
  multiplier: 2.0

logging:
  level: "info"
```

## Running Tests

```bash
# Proxy server (142 tests)
cd proxy-server && pnpm test

# Local agent (36 tests)
cd local-agent && cargo test
```

## Project Structure

```
Guardian/
  proxy-server/           # Node.js proxy server
    src/
      proxy/              # CONNECT proxy, MITM, passthrough
      tunnel/             # Binary protocol, session manager, tunnel server
      injection/          # Placeholder scanning and secret injection
      secrets/            # Secret providers (env, AWS)
      auth/               # Client authentication
      audit/              # JSONL audit logging
    tests/                # 142 tests (unit + integration)
    config/               # Example server config
    certs/                # CA certificate (generated)

  local-agent/            # Rust local agent
    src/
      tunnel/             # Binary protocol, TLS client, multiplexer
      platform/           # OS-specific: interception, CA cert, service mgmt
        windows.rs        # System proxy, certutil, sc.exe
        windivert.rs      # WinDivert packet interception (Windows)
        linux.rs          # iptables, ca-certificates, systemd
      main.rs             # CLI (run, test, status, install, uninstall, service)
      agent.rs            # Orchestrator lifecycle
      local_proxy.rs      # HTTP CONNECT proxy (port 19080)
      transparent.rs      # Transparent TCP listener (port 19443)
      sni.rs              # TLS ClientHello SNI extraction
      health.rs           # Health endpoint (port 19876)
      state.rs            # Install state persistence
      config.rs           # YAML configuration
    tests/                # 36 tests (protocol + SNI parser)
    config/               # Example agent config
```

## Security Model

- Secrets exist only on the proxy server, never on developer machines
- All traffic between agent and proxy is encrypted (TLS tunnel with binary framing)
- Authentication required for both proxy access and tunnel connections
- Domain-bound secrets: `__OPENAI_KEY__` only injects for `api.openai.com` (anti-exfiltration)
- Timing-safe token comparison prevents timing attacks
- JSONL audit log records every injection (never logs secret values)
- Transparent mode excludes agent's own traffic from interception (WinDivert: tunnel server IP filter; Linux: iptables `--uid-owner` exclusion)

## How Transparent Interception Works

### Windows

Guardian supports two interception methods on Windows:

**WinDivert (default with `method: auto`)** — Intercepts at the **network packet level** using the [WinDivert](https://reqrypt.org/windivert.html) driver. Captures ALL outbound TCP:443 traffic regardless of whether the application respects proxy settings. The agent NAT-rewrites packet destinations to `127.0.0.1:19443` (transparent listener), and reverse-NATs the responses so the application sees the original server address. Requires administrator privileges. The WinDivert driver is compiled from source via the `vendored` feature — no separate driver installation needed.

**System proxy (fallback, or `method: system_proxy`)** — Configures the Windows system proxy via the registry (`HKCU\...\Internet Settings`). Applications that respect the system proxy (browsers, curl, most HTTP clients) route through the agent automatically. A `ProxyOverride` bypass list excludes `localhost` and `127.0.0.1`. Does not require driver signing, but misses apps that ignore the proxy setting.

### Linux

The agent adds an **iptables REDIRECT** rule that sends all outbound TCP:443 traffic to the transparent listener (port 19443). A `--uid-owner` exclusion ensures the agent's own tunnel traffic isn't redirected (prevents infinite loops).

### SNI Extraction

The transparent listener `peek()`s at the first bytes of each connection without consuming them, parses the TLS ClientHello to extract the Server Name Indication (SNI) hostname, and routes accordingly. The original ClientHello bytes remain in the buffer so the proxy server can perform its normal MITM handshake.

## Tunnel Protocol

The agent and proxy communicate over a custom binary framing protocol multiplexed over a single TLS connection:

```
[Connection ID: 4B BE] [Frame Type: 1B] [Payload Length: 4B BE] [Payload]
```

Frame types: `NEW_CONNECTION`, `DATA`, `CLOSE`, `AUTH`, `AUTH_OK`, `AUTH_FAIL`, `HEARTBEAT`, `HEARTBEAT_ACK`

Cross-language compatibility is verified by identical hex fixture tests in both Node.js and Rust.

## Roadmap

- [x] Phase 1: Binary tunnel protocol (Node.js + Rust)
- [x] Phase 2: Node.js tunnel server
- [x] Phase 3: Rust agent core (local CONNECT proxy)
- [x] Phase 4: SNI extraction + transparent listener
- [x] Phase 5: OS-level interception (Windows system proxy + WinDivert, Linux iptables)
- [x] Phase 6: Service management, CA cert install, full CLI
- [ ] Phase 7: Hardening (crash safety, reconnection, resource limits)

## License

MIT
