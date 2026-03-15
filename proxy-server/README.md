# Guardian Proxy Server

A secret-injecting HTTPS proxy. Clients connect through the proxy and use `__PLACEHOLDER__` tokens in their request headers. The proxy intercepts TLS traffic, resolves the real secrets from configured providers (environment variables, AWS Secrets Manager), and injects them before forwarding to the target API — so secrets never exist on the client machine.

## How It Works

```
Your app                          Guardian Proxy                    Target API
   │                                   │                               │
   │─── CONNECT api.openai.com:443 ───►│                               │
   │◄── 200 Connection Established ────│                               │
   │─── TLS handshake (proxy CA) ─────►│                               │
   │                                   │                               │
   │─── GET /v1/models ──────────────►│                               │
   │    Authorization: Bearer          │                               │
   │      __OPENAI_API_KEY__           │                               │
   │                                   │── GET /v1/models ───────────►│
   │                                   │   Authorization: Bearer       │
   │                                   │     sk-real-secret-key        │
   │                                   │                               │
   │                                   │◄── 200 OK ───────────────────│
   │◄── 200 OK ───────────────────────│                               │
```

1. Client sets `HTTPS_PROXY` and makes normal HTTPS requests with placeholder tokens
2. Proxy authenticates the client (Basic auth from the proxy URL)
3. Proxy performs MITM on configured domains — decrypts, scans for `__PLACEHOLDER__` patterns
4. Placeholders are matched against domain-bound secret configs (anti-exfiltration)
5. Real secrets are resolved, injected, and the request is forwarded over TLS to the real target
6. Response streams back to the client untouched

## Running Locally

### Prerequisites

- **Node.js 20+**
- **pnpm** (`npm install -g pnpm`)

### 1. Install dependencies

```bash
cd proxy-server
pnpm install
```

### 2. Generate a local CA certificate

```bash
pnpm run generate-ca
```

This creates `certs/ca.crt` and `certs/ca.key`. The proxy uses this CA to sign per-hostname certificates for MITM interception.

### 3. Create a config file

Copy the example and edit it:

```bash
cp config/server-config.example.yaml config/server-config.yaml
```

Here's a minimal local config using only environment variable secrets:

```yaml
proxy:
  port: 8080
  host: "127.0.0.1"

ca:
  certFile: "certs/ca.crt"
  keyFile: "certs/ca.key"

secrets:
  OPENAI_API_KEY:
    provider: "env"
    path: "OPENAI_API_KEY"
    allowedDomains: ["api.openai.com"]

cache:
  enabled: true
  defaultTtlSeconds: 300

auth:
  enabled: true
  clients:
    - machineId: "local"
      token: "my-local-token"

bypass:
  domains: []

aws:
  region: "us-east-1"

logging:
  level: "info"
  audit:
    enabled: false
```

### 4. Set your secrets as environment variables

```bash
# Linux/macOS
export OPENAI_API_KEY="sk-your-real-key-here"

# Windows (PowerShell)
$env:OPENAI_API_KEY = "sk-your-real-key-here"

# Windows (cmd)
set OPENAI_API_KEY=sk-your-real-key-here
```

### 5. Start the proxy

```bash
# Development mode (auto-reload)
pnpm run dev

# Or build + run production
pnpm run build
node dist/index.js config/server-config.yaml
```

You should see:

```
INFO: Configuration loaded { configPath: "config/server-config.yaml" }
INFO: CA certificate loaded
INFO: Proxy server started { port: 8080, host: "127.0.0.1" }
```

### 6. Test with curl

```bash
# Linux/macOS — trust the proxy's CA cert
HTTPS_PROXY=http://local:my-local-token@127.0.0.1:8080 \
  curl --cacert certs/ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"

# Windows — curl uses Schannel which ignores --cacert,
# so use -k to skip TLS verification for local testing
HTTPS_PROXY=http://local:my-local-token@127.0.0.1:8080 \
  curl -k \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

The proxy replaces `__OPENAI_API_KEY__` with the real key before the request reaches OpenAI.

> **Windows note**: Windows curl uses Schannel (the native TLS backend) which does not support `--cacert`. For local testing, use `-k` to skip certificate verification. For production, install the CA cert into the Windows trust store (see [Trusting the CA on Windows](#trusting-the-ca-on-windows) below).

### 7. Test without a real API (fully offline)

You can verify the proxy works without any real API keys by using a local mock HTTPS server. The integration tests do exactly this — see `tests/integration/proxy-e2e.test.ts` for the pattern.

Quick smoke test:

```bash
pnpm test
```

All 157 tests run locally with no external dependencies.

## Configuration Reference

### `proxy`
| Field | Default | Description |
|-------|---------|-------------|
| `port` | `8080` | Proxy listen port |
| `host` | `0.0.0.0` | Proxy bind address |

### `ca`
| Field | Default | Description |
|-------|---------|-------------|
| `certFile` | `certs/ca.crt` | Path to CA certificate |
| `keyFile` | `certs/ca.key` | Path to CA private key |

### `secrets`
Map of placeholder name to secret config:

```yaml
secrets:
  PLACEHOLDER_NAME:
    provider: "env"          # "env", "aws", or "stored" (panel-managed)
    path: "ENV_VAR_NAME"     # env var name or AWS secret ARN/name
    field: "json_field"      # optional: extract a field from JSON secret
    allowedDomains:          # domains where this secret can be injected
      - "api.example.com"
      - "*.example.com"      # wildcard supported
```

**Anti-exfiltration**: If a request to `evil.com` contains `__OPENAI_API_KEY__` but the secret's `allowedDomains` only includes `api.openai.com`, the placeholder is removed (not injected) and a warning is logged.

### `cache`
| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable secret value caching |
| `defaultTtlSeconds` | `300` | Cache TTL in seconds |

### `auth`
| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Require proxy authentication |
| `clients` | `[]` | List of `{ machineId, token }` pairs |

Clients authenticate via the proxy URL: `http://machineId:token@host:port`.

### `bypass`
| Field | Default | Description |
|-------|---------|-------------|
| `domains` | `[]` | Domains to pass through without MITM |

Supports exact match, wildcards (`*.internal.corp`), IP globs (`10.*`), and CIDR (`10.0.0.0/8`).

### `aws`
| Field | Default | Description |
|-------|---------|-------------|
| `region` | `us-east-1` | AWS region for Secrets Manager |

Only initialized if any secret uses `provider: "aws"`.

### `logging`
| Field | Default | Description |
|-------|---------|-------------|
| `level` | `info` | Log level (trace/debug/info/warn/error/fatal/silent) |
| `audit.enabled` | `true` | Enable JSONL audit logging |
| `audit.file` | — | Audit log file path (e.g., `logs/audit.jsonl`) |

### `panel` (optional)
| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable the admin panel |
| `port` | `9090` | Panel listen port |
| `host` | `127.0.0.1` | Panel bind address (`0.0.0.0` for network access — shows warning) |
| `dbPath` | `data/guardian.db` | SQLite database file path |
| `defaultAdminPassword` | `change-me-immediately` | Initial admin password (must change on first login) |
| `sessionTtlHours` | `24` | Login session duration in hours |
| `encryptionKeyFile` | `data/encryption.key` | AES-256 key file for stored secrets (auto-generated if missing) |

## Admin Panel

The admin panel is an opt-in web UI for managing clients, secrets, and viewing audit logs at runtime — without editing YAML files.

### Enabling the panel

Add the `panel` section to your config:

```yaml
panel:
  enabled: true
  port: 9090
  host: "127.0.0.1"
  dbPath: "data/guardian.db"
  defaultAdminPassword: "change-me-immediately"
  sessionTtlHours: 24
  encryptionKeyFile: "data/encryption.key"
```

Then start the server normally:

```bash
pnpm run dev
```

You should see:

```
INFO: Proxy server started { port: 8080, host: "0.0.0.0" }
INFO: Admin panel started { port: 9090, host: "127.0.0.1" }
```

Open `http://localhost:9090/panel/` in your browser. Log in with username `admin` and the `defaultAdminPassword`. You will be forced to change the password on first login.

### What you can do in the panel

- **Clients**: Create, enable/disable, and delete clients. Tokens are generated automatically and shown once on creation — copy them immediately.
- **Secrets**: Configure secrets with three provider types:
  - `env` — reads from environment variables (same as YAML config)
  - `aws` — reads from AWS Secrets Manager
  - `stored` — encrypted directly in the database (AES-256-GCM)
- **Audit log**: Browse paginated request logs with filters by client and action. Dashboard shows aggregate stats (total requests, injections, unique clients, last 24h activity).
- **Settings**: Change admin password, view system info (version, uptime, ports).

### Backward compatibility

Enabling the panel does not break existing YAML-based configuration:

- YAML `auth.clients` are automatically migrated to the database on startup (tokens are hashed)
- The `CompositeAuthBackend` checks the database first, then falls back to YAML config
- YAML `secrets` continue to work alongside panel-managed secrets
- JSONL audit logging continues to work — the panel adds SQLite as a second audit sink

### Network access

By default the panel binds to `127.0.0.1` (localhost only). To access it from another machine, set `host: "0.0.0.0"` — the panel will show a warning banner reminding you that it is network-exposed. For production, use an SSH tunnel instead:

```bash
ssh -L 9090:localhost:9090 your-server
```

### Security

- Admin passwords are hashed with bcrypt (cost factor 12)
- Client tokens are 32 random bytes (hex), stored as SHA-256 hashes, compared with `timingSafeEqual`
- Stored secrets are encrypted with AES-256-GCM; the key lives in a separate file (not in the YAML config)
- Login is rate-limited to 5 attempts per IP per minute
- Session cookies are `HttpOnly` + `SameSite=Strict`
- All mutating API calls require `Content-Type: application/json` (CSRF protection)

## Docker

```bash
# Build
docker build -t guardian-proxy .

# Run
docker run -p 8080:8080 \
  -v ./config:/app/config \
  -v ./certs:/app/certs \
  -e OPENAI_API_KEY=sk-your-key \
  guardian-proxy
```

## Client Configuration

Any HTTP client that supports `HTTPS_PROXY` works:

```bash
# curl (Linux/macOS)
HTTPS_PROXY=http://local:my-local-token@127.0.0.1:8080 \
  curl --cacert certs/ca.crt https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"

# curl (Windows — use -k for local dev)
HTTPS_PROXY=http://local:my-local-token@127.0.0.1:8080 \
  curl -k https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"

# Python (requests)
import os
os.environ["HTTPS_PROXY"] = "http://local:my-local-token@127.0.0.1:8080"
os.environ["REQUESTS_CA_BUNDLE"] = "certs/ca.crt"

import requests
r = requests.get("https://api.openai.com/v1/models",
                  headers={"Authorization": "Bearer __OPENAI_API_KEY__"})

# Node.js (with global-agent or undici)
# Set HTTPS_PROXY env var + NODE_EXTRA_CA_CERTS=certs/ca.crt
```

**Important**: Clients must trust the proxy's CA certificate (`certs/ca.crt`), otherwise TLS verification will fail. Use `--cacert`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, or install it in the system trust store.

### Trusting the CA on Windows

Windows curl and most Windows apps use the system certificate store (Schannel), so `--cacert` has no effect. Options:

1. **Quick testing**: Use `curl -k` to skip verification (fine for local dev)

2. **Install the CA into the Windows trust store** (makes all apps trust it):
   ```powershell
   # Run as Administrator
   certutil -addstore -f "ROOT" certs\ca.crt
   ```
   To remove it later:
   ```powershell
   certutil -delstore "ROOT" "Guardian Proxy CA"
   ```

3. **Per-tool overrides**:
   - **Node.js**: `set NODE_EXTRA_CA_CERTS=certs\ca.crt`
   - **Python requests**: `set REQUESTS_CA_BUNDLE=certs\ca.crt`
   - **Git Bash curl with OpenSSL**: If you install curl with OpenSSL backend, `--cacert` works normally

## Development

```bash
pnpm test             # run all tests
pnpm test:watch       # watch mode
pnpm run lint         # type-check (tsc --noEmit)
pnpm run build        # production build → dist/
```
