# Guardian Proxy Server

The proxy server is the central Guardian service. It authenticates clients and agents, performs HTTPS MITM for approved domains, resolves secrets server-side, injects placeholders, and optionally exposes the tunnel server and admin panel.

## Responsibilities

- authenticate direct proxy clients and tunnel sessions
- terminate TLS for approved domains
- resolve secrets from environment variables, AWS Secrets Manager, or stored panel-managed secrets
- enforce per-secret `allowedDomains`
- forward traffic upstream, preferring HTTP/2 when available
- expose optional audit logging, latency logging, the tunnel server, and the admin panel

## Quick Start

### 1. Install dependencies and generate certificates

```bash
cd proxy-server
pnpm install
pnpm run generate-ca
cp config/server-config.example.yaml config/server-config.yaml
```

If remote local-agent instances will connect to this server, also generate a tunnel certificate for the public hostname or IP:

```bash
pnpm run generate-tunnel-cert proxy.example.com
```

### 2. Configure the server

Start with `config/server-config.example.yaml` and review:

- `proxy.host`, `proxy.port`, and `proxy.publicHost`
- `ca.certFile` and `ca.keyFile`
- `secrets`
- `auth.clients`
- `logging`
- `tunnel` if remote agents are used
- `panel` if runtime management is needed

Minimal local example:

```yaml
proxy:
  host: "127.0.0.1"
  port: 8080

ca:
  certFile: "certs/ca.crt"
  keyFile: "certs/ca.key"

secrets:
  OPENAI_API_KEY:
    provider: "env"
    path: "OPENAI_API_KEY"
    allowedDomains: ["api.openai.com"]

auth:
  enabled: true
  clients:
    - machineId: "local"
      token: "change-me"

logging:
  level: "info"
  audit:
    enabled: false
```

### 3. Start the server

```bash
export OPENAI_API_KEY="sk-your-real-key"
pnpm run dev
```

Or build and run the production bundle:

```bash
pnpm run build
node dist/index.js config/server-config.yaml
```

### 4. Verify with curl

```bash
HTTPS_PROXY=http://local:change-me@127.0.0.1:8080 \
  curl --cacert certs/ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

On Windows, `curl` uses the system trust store and ignores `--cacert`; use `-k` for a quick smoke test or import the CA into the Windows trust store.

## Remote-Agent Deployments

When the proxy server will accept connections from `local-agent` machines:

- set `proxy.publicHost` to the externally reachable hostname or IP
- enable `tunnel`
- generate and reference `certs/tunnel.crt` and `certs/tunnel.key`
- create a unique `auth.clients` entry for each machine

Example tunnel block:

```yaml
tunnel:
  enabled: true
  host: "0.0.0.0"
  port: 8443
  tls:
    certFile: "certs/tunnel.crt"
    keyFile: "certs/tunnel.key"
  heartbeatIntervalMs: 30000
  heartbeatTimeoutMs: 90000
```

## Admin Panel

The admin panel is optional and intended for runtime management of:

- clients
- secrets
- audit logs

Enable it with:

```yaml
panel:
  enabled: true
  host: "127.0.0.1"
  port: 9090
  dbPath: "data/guardian.db"
  defaultAdminPassword: "change-me-immediately"
  sessionTtlHours: 24
  encryptionKeyFile: "data/encryption.key"
```

Operational guidance:

- keep it on `127.0.0.1` unless you have a deliberate access plan
- change the default admin password immediately
- back up both `data/guardian.db` and `data/encryption.key`
- prefer SSH port-forwarding over broad network exposure

## Docker

```bash
docker build -t guardian-proxy .
docker run --rm \
  -p 8080:8080 \
  -v ./config:/app/config \
  -v ./certs:/app/certs \
  guardian-proxy config/server-config.yaml
```

Persist `data/` as well if you enable the admin panel.

## Commands

```bash
pnpm run dev
pnpm run build
pnpm run lint
pnpm test
pnpm run generate-ca
pnpm run generate-tunnel-cert <hostname-or-ip>
```

## More Documentation

- [Repository Quick Start](../docs/quickstart.md)
- [Deployment Guide](../docs/deployment.md)
- [Architecture](../docs/architecture.md)
- [Repository README](../README.md)
