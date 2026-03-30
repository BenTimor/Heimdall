# Guardian Proxy Server

Secret-injecting HTTPS CONNECT proxy. Clients set `HTTPS_PROXY=http://machineId:token@host:port`, send requests with `__PLACEHOLDER__` patterns in headers, and the proxy resolves and injects real secrets before forwarding to the target.

> **Keep this file updated** when adding modules, changing architecture, or discovering new patterns.

## Quick Reference

```bash
pnpm install          # install deps
pnpm run build        # tsup → dist/
pnpm run dev          # tsx src/index.ts (hot reload)
pnpm test             # vitest run (all 169 tests)
pnpm test:watch       # vitest in watch mode
pnpm run lint         # tsc --noEmit
pnpm run generate-ca  # create certs/ca.crt + ca.key
```

## Architecture

```
Client (HTTPS_PROXY) → CONNECT → ProxyServer
  ├── Auth check (Basic, timing-safe)
  ├── Bypass domain? → Passthrough (bidirectional TCP pipe)
  └── Has secrets for domain? → MITM
        ├── Generate per-host TLS cert (signed by local CA)
        ├── Terminate TLS → negotiate client ALPN (`h2` or `http/1.1`)
        ├── Scan for __PLACEHOLDERS__
        ├── Resolve secrets (env/AWS) → Inject into headers
        ├── Forward to real target (prefer upstream `h2`, fall back to `http/1.1`)
        └── Stream response back to client

Agent (Rust) → TLS → TunnelServer
  ├── AUTH frame → Authenticator → AUTH_OK/AUTH_FAIL
  ├── NEW_CONNECTION → VirtualSocket → ProxyServer.handleTunnelConnection()
  ├── DATA frames ↔ VirtualSocket (bidirectional multiplexing)
  ├── CLOSE → destroy VirtualSocket
  └── HEARTBEAT ↔ HEARTBEAT_ACK (keepalive)
```

## Project Structure

```
src/
  index.ts                  # Entry point: loads config, wires deps, starts server + tunnel
  config/
    schema.ts               # Zod schemas (ServerConfig, TunnelConfig, and sub-schemas)
    loader.ts               # YAML → parse → validate
  proxy/
    server.ts               # ProxyServer class (CONNECT handler + handleTunnelConnection)
    mitm.ts                 # MITM handler: TLS terminate → ALPN/client protocol handling → inject → forward
    passthrough.ts          # Bidirectional TCP pipe (tunnelMode skips 200 response)
    http-parser.ts          # SocketReader + HTTP/1.1 parser helpers for upstream streaming paths
    cert-manager.ts         # Per-hostname TLS cert generation (node-forge)
    upstream-http2-pool.ts  # Reusable upstream HTTP/2 session manager + ALPN fallback cache
  tunnel/
    protocol.ts             # Binary frame encode/decode (FrameType, Frame, FrameDecoder)
    session-manager.ts      # AgentSession, SessionManager, VirtualSocket (Duplex stream)
    tunnel-server.ts        # TLS server: auth, frame dispatch, heartbeat checker
  injection/
    scanner.ts              # Scan headers for __PLACEHOLDER__ patterns
    injector.ts             # Orchestrates scan → resolve → replace per header
  secrets/
    types.ts                # SecretProvider interface
    cache.ts                # TTL map cache with lazy eviction
    resolver.ts             # Cache-through resolver (provider → cache)
    env-provider.ts         # process.env provider
    aws-provider.ts         # AWS Secrets Manager provider
    stored-provider.ts      # Decrypts stored secrets from SQLite
  auth/
    auth-backend.ts         # AuthBackend interface + ClientLookup type
    authenticator.ts        # Authenticator class (accepts AuthBackend)
    config-backend.ts       # ConfigAuthBackend — wraps YAML config clients
    db-backend.ts           # DbAuthBackend — reads from SQLite clients table
    composite-backend.ts    # CompositeAuthBackend — DB-first, config fallback
  audit/
    audit-logger.ts         # Dual-sink audit log: JSONL + SQLite (optional)
  panel/
    server.ts               # Fastify admin panel server (port 9090)
    auth.ts                 # Session management, bcrypt password helpers
    routes/
      auth.ts               # Login, logout, change-password (rate limited)
      clients.ts            # Client CRUD + token regeneration
      secrets.ts            # Secret CRUD (never returns values)
      audit.ts              # Paginated audit log + stats
      system.ts             # System info endpoint
    db/
      database.ts           # SQLite init + migration runner (WAL mode)
      crypto.ts             # AES-256-GCM encrypt/decrypt helpers
      clients.ts            # Client query functions
      secrets.ts            # Secret query functions
      audit.ts              # Audit query functions
      migrate-config.ts     # Migrate YAML clients → DB on startup
    public/
      index.html            # SPA shell
      app.js                # Vanilla JS SPA (hash-based routing)
      style.css             # Pico-inspired CSS
  utils/
    logger.ts               # Pino logger factory
    domain-matcher.ts       # Exact, wildcard (*.foo.com), IP glob, CIDR matching
scripts/
  generate-ca.ts            # Generates RSA 4096 CA cert+key
config/
  server-config.example.yaml
tests/
  integration/
    proxy-e2e.test.ts       # Full CONNECT→MITM→inject→verify flow
    proxy-hardening.test.ts # POST bodies, concurrency, error cases
    tunnel-e2e.test.ts      # Mock tunnel client → binary protocol → proxy → verify injection
  tunnel-protocol.test.ts   # Roundtrip, partial delivery, cross-language hex fixtures
  session-manager.test.ts   # VirtualSocket data flow, session CRUD
  tunnel-server.test.ts     # Auth flow, heartbeat, session lifecycle
  *.test.ts                 # Unit tests for each module
```

## Key Patterns

### Config (Zod)
All config is validated through `ServerConfigSchema` in `src/config/schema.ts`. YAML config file path: CLI arg → `GUARDIAN_CONFIG` env → `config/server-config.yaml`.

`proxy` now also carries latency/performance knobs:
- `proxy.tcpNoDelay` — disables Nagle's algorithm on proxy-side sockets (defaults to `true`)
- `proxy.connectionPool.*` — enables/tunes upstream TLS keep-alive reuse and client-side TLS session resumption to hot origins
- `logging.latency.enabled` — emits structured per-connection / per-request timing logs for MITM and tunnel ingress

Optional `tunnel` config enables the tunnel server (`TunnelConfigSchema`): port, host, TLS cert/key, heartbeat intervals.

Optional `panel` config enables the admin panel (`PanelConfigSchema`): port, host, dbPath, defaultAdminPassword, sessionTtlHours, encryptionKeyFile.

### Tunnel Protocol (Binary Framing)
Frame format: `[ConnID: 4B BE][Type: 1B][PayloadLen: 4B BE][Payload]`. Header = 9 bytes. Max payload = 65536 bytes. ConnID 0 = control channel.

Frame types: NEW_CONNECTION(0x01), DATA(0x02), CLOSE(0x03), AUTH(0x04), AUTH_OK(0x05), AUTH_FAIL(0x06), HEARTBEAT(0x07), HEARTBEAT_ACK(0x08), DOMAIN_LIST_REQUEST(0x09), DOMAIN_LIST_RESPONSE(0x0A).

Cross-language compatible — hardcoded hex fixtures verified in both Node.js and Rust test suites.

### Tunnel Server (`tunnel-server.ts`)
- Accepts TLS connections on separate port (uses real server cert, not the MITM CA)
- Sets `TCP_NODELAY` on accepted tunnel sockets when `proxy.tcpNoDelay` is enabled
- AUTH frame with "machineId:token" → validated via existing Authenticator
- Dispatches frames: NEW_CONNECTION creates VirtualSocket → routes to `ProxyServer.handleTunnelConnection()`
- When `logging.latency.enabled` is on, logs `machineId` + `connId` for NEW_CONNECTION timing correlation with the agent/proxy MITM logs
- VirtualSocket extends Duplex: writes become DATA frames, DATA frames become readable data
- Heartbeat checker disconnects stale agents after timeout
- DOMAIN_LIST_REQUEST → calls `ProxyServer.getSecretDomains()` → responds with DOMAIN_LIST_RESPONSE (JSON array of domain patterns)

### Tunnel Mode (MITM + Passthrough)
When `tunnelMode: true` in MitmDeps or PassthroughOptions:
- Skip writing "HTTP/1.1 200 Connection Established" (agent already started TLS handshake)
- `ProxyServer.handleTunnelConnection()` uses this for all tunnel-originated connections

### Secret Injection Flow
1. `scanner.ts` finds `__([A-Z][A-Z0-9_]{1,63})__` in header values
2. `injector.ts` checks each match against `config.secrets[name].allowedDomains`
3. Domain mismatch → placeholder removed (anti-exfiltration), logged as warning
4. Domain match → `resolver.resolve(provider, path, field?)` → cache-through → replace

### HTTP Parser (`http-parser.ts`)
Custom `SocketReader` class with internal buffer and async read helpers (`readUntil`, `readExact`, `readSome`, `readLine`). Handles Content-Length and chunked transfer encoding. The parser detaches from the socket after reading so MITM can reuse it for keep-alive loops.

### MITM (`mitm.ts`)
- Client-facing MITM now negotiates `h2` or `http/1.1` via ALPN and handles both through a per-connection secure server compatibility layer
- Upstream forwarding prefers pooled HTTP/2 sessions when the origin negotiates `h2`; otherwise it falls back to the existing HTTP/1.1 TLS path
- The custom `http-parser.ts` helpers are still used for raw upstream HTTP/1.1 response parsing/streaming and for request/response framing translation between H1 and H2
- Fixed-length upstream responses are streamed incrementally back to the client instead of being fully buffered first
- When `logging.latency.enabled` is on, MITM logs connection timing (cert cache/generation, TLS handshake, client ALPN/protocol) and per-request timing (`waitForRequestMs`, `headerParseMs`, `clientPassiveWaitMs`, `activeHandlingMs`, upstream protocol, pool/session reuse, TLS session reuse, response headers, response streaming, total)

### Admin Panel (`panel/`)
- Fastify server on separate port (default 9090), opt-in via `panel.enabled: true`
- SQLite (better-sqlite3) stores admins, clients, secrets, sessions, audit logs
- `AuthBackend` interface decouples auth from config: `ConfigAuthBackend` (YAML), `DbAuthBackend` (SQLite), `CompositeAuthBackend` (DB-first fallback)
- `ProxyServer` accepts `Authenticator` via deps (no longer creates its own)
- `ProxyServer.secretsConfig` is mutable — panel calls `reloadSecrets()` on changes, which merges YAML + DB secrets
- `MitmDeps.secretsConfig` replaces `MitmDeps.config` for secrets lookup
- Stored secrets: AES-256-GCM encrypted in SQLite, key in separate file (`panel.encryptionKeyFile`)
- `AuditLogger` dual-writes to JSONL + SQLite when DB is provided
- Vanilla SPA frontend (no build step): hash-based routing, Pico-inspired CSS
- Session cookies: HttpOnly + SameSite=Strict, hourly expired session cleanup
- YAML clients are auto-migrated to DB on startup (`migrateConfigClients`)

### Testing
- **Unit tests**: Mock dependencies, test each module in isolation
- **Integration tests**: Real `ProxyServer` + mock HTTPS/HTTP2 targets + raw socket CONNECT + TLS upgrade
- **Tunnel E2E tests**: Mock tunnel client / virtual tunnel socket → inject → verify, including client-facing HTTP/2 over tunnel mode
- Tests use `targetTlsOptions: { rejectUnauthorized: false }` since mock targets have self-signed certs
- Test response parsers handle chunked transfer encoding
- `proxy-hardening.test.ts` includes a delayed fixed-length response case to ensure MITM streams the body before the upstream response fully completes

## Conventions

- **ESM only** (`"type": "module"`, `.js` extensions in imports)
- **Strict TypeScript** (ES2022, Node16 module resolution)
- Node 20+ required
- pnpm as package manager
- Vitest for testing (globals enabled, 15s timeout)
- No eslint/prettier configured — use `pnpm run lint` (tsc --noEmit) for type checking

## Known Decisions

- **Keep-alive upstream by default**: MITM prefers pooled upstream TLS connections; when pooling is disabled it falls back to `Connection: close`
- **TLS session tickets cached per host**: when a pooled upstream socket is unavailable, new TLS connects offer the last cached session/ticket for that host:port to reduce handshake cost on reconnects
- **Pre-generated leaf key pool**: `CertManager` keeps a small async warm pool of RSA keypairs so first-use cert issuance can often skip synchronous key generation
- **Latency logs are opt-in**: `logging.latency.enabled` emits structured timing logs without changing the trust model or wire protocol
- **Auth defaults to enabled**: `auth.enabled` defaults to `true` in schema
- **No plain HTTP proxy**: Server returns 405 for non-CONNECT requests
- **Audit logger uses buffered writes**: JSONL/SQLite audit entries are buffered and periodically flushed to reduce request-path overhead
- **Tunnel server uses separate TLS cert**: Not the MITM CA — agent verifies server identity

## Docker

```bash
docker build -t guardian-proxy .
docker run -p 8080:8080 -v ./config:/app/config -v ./certs:/app/certs guardian-proxy
```

Multi-stage build: `node:20-slim` builder + slim runtime. Entry: `node dist/index.js config/server-config.yaml`.
