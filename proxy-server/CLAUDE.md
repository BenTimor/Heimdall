# Guardian Proxy Server

Secret-injecting HTTPS CONNECT proxy. Clients set `HTTPS_PROXY=http://machineId:token@host:port`, send requests with `__PLACEHOLDER__` patterns in headers, and the proxy resolves and injects real secrets before forwarding to the target.

> **Keep this file updated** when adding modules, changing architecture, or discovering new patterns.

## Quick Reference

```bash
pnpm install          # install deps
pnpm run build        # tsup → dist/
pnpm run dev          # tsx src/index.ts (hot reload)
pnpm test             # vitest run (all 157 tests)
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
        ├── Decrypt → Parse HTTP/1.1 → Scan for __PLACEHOLDERS__
        ├── Resolve secrets (env/AWS) → Inject into headers
        ├── Forward to real target (with Connection: close)
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
    mitm.ts                 # MITM handler: TLS wrap → parse → inject → forward (tunnelMode)
    passthrough.ts          # Bidirectional TCP pipe (tunnelMode skips 200 response)
    http-parser.ts          # SocketReader + parseHttpRequest/serializeHttpRequest
    cert-manager.ts         # Per-hostname TLS cert generation (node-forge)
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

Optional `tunnel` config enables the tunnel server (`TunnelConfigSchema`): port, host, TLS cert/key, heartbeat intervals.

Optional `panel` config enables the admin panel (`PanelConfigSchema`): port, host, dbPath, defaultAdminPassword, sessionTtlHours, encryptionKeyFile.

### Tunnel Protocol (Binary Framing)
Frame format: `[ConnID: 4B BE][Type: 1B][PayloadLen: 4B BE][Payload]`. Header = 9 bytes. Max payload = 65536 bytes. ConnID 0 = control channel.

Frame types: NEW_CONNECTION(0x01), DATA(0x02), CLOSE(0x03), AUTH(0x04), AUTH_OK(0x05), AUTH_FAIL(0x06), HEARTBEAT(0x07), HEARTBEAT_ACK(0x08).

Cross-language compatible — hardcoded hex fixtures verified in both Node.js and Rust test suites.

### Tunnel Server (`tunnel-server.ts`)
- Accepts TLS connections on separate port (uses real server cert, not the MITM CA)
- AUTH frame with "machineId:token" → validated via existing Authenticator
- Dispatches frames: NEW_CONNECTION creates VirtualSocket → routes to `ProxyServer.handleTunnelConnection()`
- VirtualSocket extends Duplex: writes become DATA frames, DATA frames become readable data
- Heartbeat checker disconnects stale agents after timeout

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
Custom `SocketReader` class with internal buffer and async read helpers (`readUntil`, `readExact`, `readLine`). Handles Content-Length and chunked transfer encoding. The parser detaches from the socket after reading so MITM can reuse it for keep-alive loops.

### MITM (`mitm.ts`)
Forces `Connection: close` on forwarded requests so the target closes the connection after responding. This simplifies response reading (wait for `end` event). The `forwardToTarget` function buffers the full response before writing to the client TLS socket.

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
- **Integration tests**: Real `ProxyServer` + mock HTTPS target + raw socket CONNECT + TLS upgrade
- **Tunnel E2E tests**: Mock tunnel client speaking binary protocol → inject → verify
- Tests use `targetTlsOptions: { rejectUnauthorized: false }` since mock targets have self-signed certs
- Test response parsers handle chunked transfer encoding

## Conventions

- **ESM only** (`"type": "module"`, `.js` extensions in imports)
- **Strict TypeScript** (ES2022, Node16 module resolution)
- Node 20+ required
- pnpm as package manager
- Vitest for testing (globals enabled, 15s timeout)
- No eslint/prettier configured — use `pnpm run lint` (tsc --noEmit) for type checking

## Known Decisions

- **Connection: close forced**: MITM forces close on all forwarded requests for simplicity
- **Auth defaults to enabled**: `auth.enabled` defaults to `true` in schema
- **No plain HTTP proxy**: Server returns 405 for non-CONNECT requests
- **Audit logger uses sync writes**: `fs.writeSync` for JSONL audit entries to avoid data loss
- **Tunnel server uses separate TLS cert**: Not the MITM CA — agent verifies server identity

## Docker

```bash
docker build -t guardian-proxy .
docker run -p 8080:8080 -v ./config:/app/config -v ./certs:/app/certs guardian-proxy
```

Multi-stage build: `node:20-slim` builder + slim runtime. Entry: `node dist/index.js config/server-config.yaml`.
