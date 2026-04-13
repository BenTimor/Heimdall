# Heimdall Quick Start

This guide walks through the recommended first-run experience for Heimdall: a fully transparent local-agent setup on a developer workstation.

Use this path when you want the developer machine to work without setting `HTTPS_PROXY` per application.

If you are validating Heimdall on a VPS, CI runner, or a workload that runs as `root`, prefer [Explicit Proxy Guide](explicit-proxy.md) first.

## Prerequisites

- Node.js 20+
- `pnpm`
- Rust 1.75+ if you want to build the local agent from source
- a real secret to inject, such as `OPENAI_API_KEY`
- elevated privileges on the developer machine for the install step:
  - Windows: run an elevated shell
  - Linux: use `sudo`

## 1. Prepare the proxy server

```bash
cd proxy-server
pnpm install
pnpm run generate-ca
pnpm run generate-tunnel-cert proxy.example.com
cp config/server-config.example.yaml config/server-config.yaml
```

Update `config/server-config.yaml`:

- set `proxy.publicHost` to the externally reachable hostname or IP of the proxy server
- add or confirm `auth.clients` entries for each developer machine
- enable the tunnel server
- define the secrets you want Heimdall to inject

Example:

```yaml
proxy:
  host: "0.0.0.0"
  port: 8080
  publicHost: "proxy.example.com"

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
      token: "some-secure-token-here"

logging:
  level: "info"
  audit:
    enabled: true

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

Start the proxy:

```bash
export OPENAI_API_KEY="sk-your-real-key"
pnpm run dev
```

## 2. Copy the Heimdall CA certificate to the developer machine

Copy `proxy-server/certs/ca.crt` from the server to the developer machine as something like `heimdall-ca.crt`.

With the current helper scripts, this certificate serves two purposes:

- it lets the agent trust the tunnel server certificate
- it is installed into the workstation trust store so apps trust Heimdall's MITM certificates

## 3. Install or build the local agent

Choose one:

- Download a prebuilt archive from the repository's Releases page when your team publishes binaries.
- Or build from source:

```bash
cd local-agent
cargo build --release
cp config/agent-config.example.yaml config/agent-config.yaml
```

Edit `config/agent-config.yaml`:

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "/path/to/heimdall-ca.crt"

auth:
  machine_id: "dev-machine-01"
  token: "some-secure-token-here"

transparent:
  enabled: true
  host: "0.0.0.0"
  port: 19443
  method: "auto"
  capture_host: true
  capture_cidrs: []
  exclude_cidrs: []
```

The `machine_id` and `token` must match an entry in the proxy server's `auth.clients`.

## 4. Install Heimdall on the developer machine

Run the install step with elevated privileges so Heimdall can install the CA certificate and enable transparent interception:

```bash
heimdall-local-agent install \
  --config ./agent-config.yaml \
  --ca-cert /path/to/heimdall-ca.crt
```

If you built from source instead of using a packaged binary:

```bash
target/release/heimdall-local-agent install \
  --config config/agent-config.yaml \
  --ca-cert /path/to/heimdall-ca.crt
```

This step:

- installs the Heimdall CA certificate into the workstation trust store
- enables transparent interception
- saves enough state for `uninstall` to reverse the changes later

Linux notes:

- transparent mode redirects outbound IPv4 and IPv6 traffic with `iptables` and `ip6tables`
- `capture_host: true` covers host-originated traffic on that machine
- `capture_cidrs` can also cover local Docker, Podman, or CNI bridge subnets on the same host
- root-owned client processes are excluded from interception to avoid tunnel loops
- for VPS or server validation, use a non-root shell for transparent-mode smoke tests or prefer [Explicit Proxy Guide](explicit-proxy.md)

## 5. Start the local agent

```bash
heimdall-local-agent run --config ./agent-config.yaml
```

If you built from source instead of using a packaged binary:

```bash
target/release/heimdall-local-agent run --config config/agent-config.yaml
```

## 6. Verify that apps work without `HTTPS_PROXY`

With the transparent install in place, applications should work without any per-process proxy configuration:

```bash
curl -4 https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

```bash
curl -6 https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

The application only sees the placeholder. The real secret is resolved and injected by the proxy server.

On Linux, run these verifications from a non-root shell. Root-owned client processes are still excluded from transparent interception to avoid tunnel loops.

## Next Steps

- If you want per-process routing instead of machine-wide interception, read [Explicit Proxy Guide](explicit-proxy.md).
- For a fuller operator guide, read [Deployment Guide](deployment.md).
- For local-agent installation and release packaging guidance, read [Local Agent Guide](local-agent.md).
- For the deeper system model, read [Architecture](architecture.md).
