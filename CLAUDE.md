# Guardian

Transparent secret injection for HTTPS traffic. Two components: a Node.js proxy server (holds secrets, performs MITM injection) and a Rust local agent (tunnels traffic from developer machines).

> **Keep this file updated** when adding modules, changing architecture, or discovering new patterns.
> See also: `proxy-server/CLAUDE.md` and `local-agent/CLAUDE.md` for component-specific details.

## Quick Reference

```bash
# Proxy server (Node.js)
cd proxy-server
pnpm install && pnpm run generate-ca
pnpm test                # 169 tests
pnpm run dev             # start dev server

# Local agent (Rust)
cd local-agent
cargo test               # 60 tests
cargo build --release
cargo run -- run          # start agent
cargo run -- install --ca-cert path/to/ca.pem  # install CA + interception
cargo run -- uninstall    # reverse install

# Dependency auditing
cd local-agent && cargo audit    # check Rust deps for vulnerabilities
cd proxy-server && pnpm audit    # check Node.js deps for vulnerabilities
```

## Repository Structure

```
Guardian/
  proxy-server/           # Node.js/TypeScript — central proxy
    src/
      proxy/              # CONNECT proxy, MITM, passthrough
      tunnel/             # Binary protocol, session manager, tunnel server
      injection/          # Placeholder scanning + secret injection
      secrets/            # Providers (env, AWS, stored)
      auth/               # AuthBackend interface, authenticator, config/db/composite backends
      audit/              # Dual-sink audit log (JSONL + SQLite)
      panel/              # Admin panel (Fastify, SQLite, vanilla SPA)
      config/             # Zod schemas + YAML loader
      utils/              # Logger, domain matcher
    tests/                # 19 test files (169 tests)

  local-agent/            # Rust — developer machine daemon
    src/
      tunnel/             # Binary protocol codec, TLS client, multiplexer
      platform/           # OS-specific: interception, CA cert, service mgmt
        mod.rs            # PlatformOps trait + factory
        windows.rs        # System proxy, certutil, sc.exe
        windivert.rs      # WinDivert packet interception (NAT rewrite)
        linux.rs          # iptables, ca-certificates, systemd
      main.rs             # CLI: run, test, status, install, uninstall, service
      agent.rs            # Lifecycle orchestrator
      config.rs           # YAML config (+ TransparentConfig + InterceptionMethod)
      domain_filter.rs    # Domain-based tunnel/direct routing
      local_proxy.rs      # HTTP CONNECT proxy (port 19080)
      transparent.rs      # Transparent TCP listener (port 19443, SNI-based)
      sni.rs              # TLS ClientHello SNI extraction
      health.rs           # Health endpoint (port 19876)
      state.rs            # Install state persistence
    tests/                # 2 test files (60 tests)
```

## Architecture

```
Developer Machine                          Server
┌──────────────────────────┐              ┌────────────────────────────────┐
│ Mode A: HTTPS_PROXY      │              │                                │
│   App → CONNECT (19080)  │  TLS tunnel  │ TunnelServer (binary framing)  │
│                          │◄────────────►│         │                      │
│ Mode B: Transparent      │              │ ProxyServer (MITM + inject)    │
│   OS redirect → SNI      │              │ SecretResolver (env/AWS)       │
│   listener (19443)       │              │                                │
│   Win: WinDivert/sysproxy│              │                                │
│   Linux: iptables        │              │                                │
│                          │              │                                │
│ Health (19876)           │              │                                │
└──────────────────────────┘              └────────────────────────────────┘
```

### Domain-based filtering
After AUTH_OK, the agent sends `DOMAIN_LIST_REQUEST` on the control channel (conn_id 0). The server responds with `DOMAIN_LIST_RESPONSE` containing a JSON array of domain patterns (exact or `*.wildcard`). The agent polls every 10 seconds. Connections to non-matching domains bypass the tunnel entirely (direct TCP passthrough), reducing latency and server load.

### Latency instrumentation
When `proxy-server` config sets `logging.latency.enabled: true`, the proxy emits structured tunnel/MITM timing logs (connection setup, negotiated client ALPN/protocol, `waitForRequestMs`, `headerParseMs`, `clientPassiveWaitMs`, `activeHandlingMs`, cert cache/generation, upstream protocol selection, pool/session reuse, TLS session reuse, response-header latency, response streaming). The local agent emits matching debug logs keyed by `conn_id` around `NEW_CONNECTION` send/close so proxy and agent timings can be correlated without changing the wire protocol.

### Data flow — Explicit proxy mode
1. App sets `HTTPS_PROXY=http://127.0.0.1:19080` and sends `Authorization: Bearer __OPENAI_KEY__`
2. Local agent accepts CONNECT, checks domain against filter
   - **No match** → direct TCP passthrough to target (no tunnel)
   - **Match** → forwards as NEW_CONNECTION frame through tunnel
3. Tunnel server creates VirtualSocket, routes to ProxyServer.handleTunnelConnection()
4. Proxy performs MITM: terminate TLS, negotiate client `h2`/`http/1.1`, scan headers, inject secrets, then forward to the real API (preferring upstream HTTP/2 with HTTP/1.1 fallback)
5. Fixed-length responses are streamed back incrementally (not fully buffered first)
6. Response flows back through the same path

### Data flow — Transparent interception mode
1. OS redirects outbound TCP:443 to transparent listener (port 19443)
   - Windows: WinDivert (packet-level NAT rewrite, captures all apps) or system proxy (registry)
   - Linux: iptables REDIRECT with UID exclusion
2. Listener peeks at TLS ClientHello, extracts hostname via SNI
3. Checks domain against filter — **no match** → direct passthrough; **match** → tunnel
4. Forwards connection as NEW_CONNECTION frame through tunnel (same as above)
4. No per-app proxy configuration needed

### Tunnel Protocol
Binary framing over TLS: `[ConnID: 4B BE][Type: 1B][PayloadLen: 4B BE][Payload]`
Frame types: NEW_CONNECTION(0x01), DATA(0x02), CLOSE(0x03), AUTH(0x04), AUTH_OK(0x05), AUTH_FAIL(0x06), HEARTBEAT(0x07), HEARTBEAT_ACK(0x08), DOMAIN_LIST_REQUEST(0x09), DOMAIN_LIST_RESPONSE(0x0A)
Cross-language compatible — identical hex fixtures in both test suites.

## Conventions

### Proxy Server (Node.js)
- ESM-only, `.js` extensions in imports, strict TypeScript
- Zod for config validation, Pino for logging, Vitest for testing
- pnpm as package manager, Node 20+

### Local Agent (Rust)
- Rust 2021 edition, tokio async runtime
- clap (derive) for CLI, serde_yaml for config, tracing for logging
- anyhow for application errors, thiserror for library errors
- DashMap for concurrent state, axum for health endpoint
- WinDivert + etherparse for Windows packet interception

## Cross-Component Contracts

### Authentication
Both CONNECT proxy and tunnel use the same credentials: `machineId:token`. Proxy uses Basic auth header; tunnel sends AUTH frame with `machineId:token` payload.

### Config alignment
Agent config `auth.machine_id` + `auth.token` must match a `clients` entry in proxy server `auth.clients`.

### NEW_CONNECTION payload
UTF-8 string: `host:port` (e.g., `api.openai.com:443`).

## Development Workflow

### Adding a new secret provider
1. Implement `SecretProvider` interface in `proxy-server/src/secrets/`
2. Register in `proxy-server/src/index.ts` provider map
3. Add provider name to config schema if needed

### Modifying the tunnel protocol
1. Update frame types in BOTH `proxy-server/src/tunnel/protocol.ts` and `local-agent/src/tunnel/protocol.rs`
2. Update cross-language hex fixtures in both test suites
3. Run both test suites to verify compatibility

### Testing end-to-end (explicit proxy)
```bash
# Terminal 1: proxy server
cd proxy-server && OPENAI_API_KEY=sk-test pnpm run dev

# Terminal 2: agent
cd local-agent && cargo run -- run --config config/agent-config.yaml

# Terminal 3: test
HTTPS_PROXY=http://127.0.0.1:19080 curl https://api.openai.com/v1/models -H "Authorization: Bearer __OPENAI_API_KEY__"
```

### Testing end-to-end (transparent interception)
```bash
# Terminal 1: proxy server
cd proxy-server && OPENAI_API_KEY=sk-test pnpm run dev

# Terminal 2: install + run (as admin/root)
cd local-agent
cargo run -- install --config config/agent-config.yaml --ca-cert ../proxy-server/certs/ca.pem
cargo run -- run --config config/agent-config.yaml

# Terminal 3: test (no HTTPS_PROXY needed!)
curl https://api.openai.com/v1/models -H "Authorization: Bearer __OPENAI_API_KEY__"

# Cleanup
cargo run -- uninstall
```

## Roadmap

- [x] Phase 1: Binary tunnel protocol (both sides)
- [x] Phase 2: Node.js tunnel server
- [x] Phase 3: Rust agent core (local CONNECT proxy)
- [x] Phase 4: SNI extraction + transparent listener
- [x] Phase 5: OS-level interception (Windows system proxy, Linux iptables)
- [x] Phase 6: Service management, CA cert install, full CLI (install/uninstall)
- [ ] Phase 7: Hardening
