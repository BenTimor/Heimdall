# Guardian Deployment Guide

This guide focuses on running the Guardian proxy server in a team or production-like environment.

## Recommended Topology

- Run `proxy-server` on a controlled host or VM.
- Keep live secrets server-side only.
- Have developers connect through the Rust local agent over the authenticated tunnel.
- Expose the admin panel only on localhost unless you intentionally front it with another secure access layer.

## Prerequisites

- Node.js 20+
- `pnpm`
- a host reachable by developer machines
- environment variables or AWS credentials for the secrets you plan to resolve

## 1. Prepare certificates

Generate the MITM CA certificate:

```bash
cd proxy-server
pnpm install
pnpm run generate-ca
```

If remote agents will connect to this server, also generate a tunnel certificate for the public hostname or IP:

```bash
pnpm run generate-tunnel-cert proxy.example.com
```

Current helper scripts generate:

- `certs/ca.crt` and `certs/ca.key` for Guardian's MITM CA
- `certs/tunnel.crt` and `certs/tunnel.key` for the tunnel server

## 2. Configure the server

Start from the example:

```bash
cp config/server-config.example.yaml config/server-config.yaml
```

At minimum, review these sections:

- `proxy.host` and `proxy.port`
- `proxy.publicHost`
- `ca.certFile` and `ca.keyFile`
- `secrets`
- `auth.clients`
- `logging`
- `tunnel` if remote agents are used
- `panel` if you want runtime management

Example production-oriented skeleton:

```yaml
proxy:
  host: "0.0.0.0"
  port: 8080
  publicHost: "proxy.example.com"
  tcpNoDelay: true

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
    - machineId: "dev-machine-01"
      token: "replace-me"

logging:
  level: "info"
  audit:
    enabled: true
    file: "logs/audit.jsonl"

tunnel:
  enabled: true
  host: "0.0.0.0"
  port: 8443
  tls:
    certFile: "certs/tunnel.crt"
    keyFile: "certs/tunnel.key"
```

## Why `proxy.publicHost` matters

Guardian includes an OCSP responder URL in generated MITM leaf certificates. Set `proxy.publicHost` to the hostname or IP clients can actually reach; otherwise the responder URL falls back to `127.0.0.1`, which only makes sense for single-machine setups.

## 3. Provide secrets securely

Guardian supports three secret sources:

- `env`: resolve from environment variables
- `aws`: resolve from AWS Secrets Manager
- `stored`: resolve from the panel-managed encrypted SQLite store

Recommendations:

- keep the CA private key and tunnel private key tightly scoped to the Guardian host
- avoid storing live secrets in the repo or example config files
- use domain allow-lists for every secret

## 4. Start the server

### Manual run

```bash
export OPENAI_API_KEY="sk-your-real-key"
pnpm run build
node dist/index.js config/server-config.yaml
```

### Development run

```bash
export OPENAI_API_KEY="sk-your-real-key"
pnpm run dev
```

### Docker

The repository already contains a Dockerfile for the proxy server:

```bash
docker build -t guardian-proxy proxy-server
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/proxy-server/config:/app/config" \
  -v "$(pwd)/proxy-server/certs:/app/certs" \
  guardian-proxy config/server-config.yaml
```

If you use the admin panel, also persist `proxy-server/data/`.

## 5. Onboard developer machines

For each developer machine:

1. create an `auth.clients` entry with a unique `machineId` and token
2. distribute the local-agent config
3. distribute trust material for the tunnel connection:
   - `server.ca_cert` pointing at the CA that signed `tunnel.crt`, or
   - `server.cert_pin` if you pin the tunnel certificate instead
4. optionally distribute the MITM CA certificate so transparent mode can install it locally

Share [Local Agent Guide](local-agent.md) with users.

## 6. Admin panel

The admin panel is optional.

Use it when you want runtime management of:

- clients
- stored or AWS-backed secret definitions
- audit logs

Guidance:

- keep `panel.host` on `127.0.0.1` unless you have an explicit access plan
- change the default admin password immediately
- back up both `data/guardian.db` and `data/encryption.key`
- prefer SSH port-forwarding for remote access

## 7. Backups And Persistence

Back up these files if they exist in your deployment:

- `config/server-config.yaml`
- `certs/ca.crt`
- `certs/ca.key`
- `certs/tunnel.crt`
- `certs/tunnel.key`
- `data/guardian.db`
- `data/encryption.key`
- audit log files such as `logs/audit.jsonl`

The encryption key and database must stay together if you use stored secrets.

## 8. Observability

Guardian already supports:

- structured proxy logging
- optional audit logs
- optional latency logging via `logging.latency.enabled`
- local-agent health and tunnel status endpoints on the workstation side

For remote deployments, centralize logs and consider alerting on:

- auth failures
- repeated tunnel disconnects
- missing or expired certificates
- unexpected domain mismatch warnings

## 9. Hardening Checklist

Before calling a deployment production-ready, verify:

- unique tokens per machine
- CA private keys stored securely
- `allowedDomains` defined for every secret
- admin panel not broadly exposed
- backups in place for config, keys, and database
- release process for the local agent includes checksums and signed binaries if possible

Also review [`../BACKLOG.md`](../BACKLOG.md), which tracks remaining hardening items such as rate limiting, certificate expiry monitoring, and config hot reload.

