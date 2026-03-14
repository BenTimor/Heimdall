# Guardian

Transparent secret injection for HTTPS traffic. Two components: a Node.js proxy server (holds secrets, performs MITM injection) and a Rust local agent (tunnels traffic from developer machines).

> **Keep this file updated** when adding modules, changing architecture, or discovering new patterns.
> See also: `proxy-server/CLAUDE.md` and `local-agent/CLAUDE.md` for component-specific details.

## Quick Reference

```bash
# Proxy server (Node.js)
cd proxy-server
pnpm install && pnpm run generate-ca
pnpm test                # 142 tests
pnpm run dev             # start dev server

# Local agent (Rust)
cd local-agent
cargo test               # 36 tests
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
      secrets/            # Providers (env, AWS Secrets Manager)
      auth/               # Basic proxy auth (timing-safe)
      audit/              # JSONL audit log
      config/             # Zod schemas + YAML loader
      utils/              # Logger, domain matcher
    tests/                # 18 test files (142 tests)

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
      local_proxy.rs      # HTTP CONNECT proxy (port 19080)
      transparent.rs      # Transparent TCP listener (port 19443, SNI-based)
      sni.rs              # TLS ClientHello SNI extraction
      health.rs           # Health endpoint (port 19876)
      state.rs            # Install state persistence
    tests/                # 2 test files (36 tests)
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

### Data flow — Explicit proxy mode
1. App sets `HTTPS_PROXY=http://127.0.0.1:19080` and sends `Authorization: Bearer __OPENAI_KEY__`
2. Local agent accepts CONNECT, forwards as NEW_CONNECTION frame through tunnel
3. Tunnel server creates VirtualSocket, routes to ProxyServer.handleTunnelConnection()
4. Proxy performs MITM: decrypt TLS → scan headers → inject secrets → forward to real API
5. Response flows back through the same path

### Data flow — Transparent interception mode
1. OS redirects outbound TCP:443 to transparent listener (port 19443)
   - Windows: WinDivert (packet-level NAT rewrite, captures all apps) or system proxy (registry)
   - Linux: iptables REDIRECT with UID exclusion
2. Listener peeks at TLS ClientHello, extracts hostname via SNI
3. Forwards connection as NEW_CONNECTION frame through tunnel (same as above)
4. No per-app proxy configuration needed

### Tunnel Protocol
Binary framing over TLS: `[ConnID: 4B BE][Type: 1B][PayloadLen: 4B BE][Payload]`
Frame types: NEW_CONNECTION(0x01), DATA(0x02), CLOSE(0x03), AUTH(0x04), AUTH_OK(0x05), AUTH_FAIL(0x06), HEARTBEAT(0x07), HEARTBEAT_ACK(0x08)
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
