# Guardian Proxy Server

Secret-injecting HTTPS CONNECT proxy. Clients set `HTTPS_PROXY=http://machineId:token@host:port`, send requests with `__PLACEHOLDER__` patterns in headers, and the proxy resolves and injects real secrets before forwarding to the target.

> **Keep this file updated** when adding modules, changing architecture, or discovering new patterns.

## Quick Reference

```bash
pnpm install          # install deps
pnpm run build        # tsup → dist/
pnpm run dev          # tsx src/index.ts (hot reload)
pnpm test             # vitest run (all 94 tests)
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
```

## Project Structure

```
src/
  index.ts                  # Entry point: loads config, wires deps, starts server
  config/
    schema.ts               # Zod schemas (ServerConfig and sub-schemas)
    loader.ts               # YAML → parse → validate
  proxy/
    server.ts               # ProxyServer class (http.Server, CONNECT handler)
    mitm.ts                 # MITM handler: TLS wrap → parse → inject → forward
    passthrough.ts          # Bidirectional TCP pipe for bypass domains
    http-parser.ts          # SocketReader + parseHttpRequest/serializeHttpRequest
    cert-manager.ts         # Per-hostname TLS cert generation (node-forge)
  injection/
    scanner.ts              # Scan headers for __PLACEHOLDER__ patterns
    injector.ts             # Orchestrates scan → resolve → replace per header
  secrets/
    types.ts                # SecretProvider interface
    cache.ts                # TTL map cache with lazy eviction
    resolver.ts             # Cache-through resolver (provider → cache)
    env-provider.ts         # process.env provider
    aws-provider.ts         # AWS Secrets Manager provider
  auth/
    authenticator.ts        # Basic proxy auth with crypto.timingSafeEqual
  audit/
    audit-logger.ts         # JSONL audit log (never logs secret values)
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
  *.test.ts                 # Unit tests for each module
```

## Key Patterns

### Config (Zod)
All config is validated through `ServerConfigSchema` in `src/config/schema.ts`. YAML config file path: CLI arg → `GUARDIAN_CONFIG` env → `config/server-config.yaml`.

### Secret Injection Flow
1. `scanner.ts` finds `__([A-Z][A-Z0-9_]{1,63})__` in header values
2. `injector.ts` checks each match against `config.secrets[name].allowedDomains`
3. Domain mismatch → placeholder removed (anti-exfiltration), logged as warning
4. Domain match → `resolver.resolve(provider, path, field?)` → cache-through → replace

### HTTP Parser (`http-parser.ts`)
Custom `SocketReader` class with internal buffer and async read helpers (`readUntil`, `readExact`, `readLine`). Handles Content-Length and chunked transfer encoding. The parser detaches from the socket after reading so MITM can reuse it for keep-alive loops.

### MITM (`mitm.ts`)
Forces `Connection: close` on forwarded requests so the target closes the connection after responding. This simplifies response reading (wait for `end` event). The `forwardToTarget` function buffers the full response before writing to the client TLS socket.

### Testing
- **Unit tests**: Mock dependencies, test each module in isolation
- **Integration tests**: Real `ProxyServer` + mock HTTPS target + raw socket CONNECT + TLS upgrade
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

- **Tunnel server deferred**: `tunnel/` modules for Rust agent integration are not yet implemented
- **Connection: close forced**: MITM forces close on all forwarded requests for simplicity
- **Auth defaults to enabled**: `auth.enabled` defaults to `true` in schema
- **No plain HTTP proxy**: Server returns 405 for non-CONNECT requests
- **Audit logger uses sync writes**: `fs.writeSync` for JSONL audit entries to avoid data loss

## Docker

```bash
docker build -t guardian-proxy .
docker run -p 8080:8080 -v ./config:/app/config -v ./certs:/app/certs guardian-proxy
```

Multi-stage build: `node:20-slim` builder + slim runtime. Entry: `node dist/index.js config/server-config.yaml`.
