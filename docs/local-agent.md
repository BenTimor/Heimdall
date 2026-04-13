# Heimdall Local Agent Guide

The local agent is the workstation-side or runner-host-side entry point for Heimdall. It provides:

- a local CONNECT proxy endpoint
- optional transparent HTTPS interception
- an authenticated TLS tunnel back to the Heimdall proxy server

For developers, this usually means a local daemon on the workstation. For the public OpenCode demo, it means a root-owned service on an ephemeral self-hosted Linux runner.

## Installation Options

### Option 1: Download a prebuilt executable

For end users, prebuilt releases are the preferred experience because they do not require a Rust toolchain.

When your team publishes binaries, distribute them from the repository's [GitHub Releases page](https://github.com/BenTimor/Heimdall/releases).

Recommended release contents:

- the platform binary:
  - `heimdall-local-agent.exe` on Windows
  - `heimdall-local-agent` on Linux
- a sample `agent-config.yaml`
- checksums
- release notes describing supported operating systems
- for Windows WinDivert mode, the required driver assets or explicit installation instructions

If a release is not yet available for your platform, build from source.

### Option 2: Build from source

```bash
cd local-agent
cargo build --release
cp config/agent-config.example.yaml config/agent-config.yaml
```

Source builds currently produce `target/release/heimdall-local-agent`.

## Basic Configuration

Start from the example file:

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "/path/to/tunnel-ca.crt"
  cert_pin: null

auth:
  machine_id: "dev-machine-01"
  token: "replace-me"

local_proxy:
  host: "127.0.0.1"
  port: 19080
  auth_token: null

health:
  host: "127.0.0.1"
  port: 19876

reconnect:
  initial_delay_ms: 1000
  max_delay_ms: 60000
  multiplier: 2.0

transparent:
  enabled: false
  host: "0.0.0.0"
  port: 19443
  method: "auto"
  capture_host: true
  capture_cidrs: []
  exclude_cidrs: []
  exclude_pids: []

logging:
  level: "info"
```

Field notes:

- `server.host` and `server.port` point to the proxy server's tunnel listener
- `server.ca_cert` is optional and should point at the CA that signed the tunnel server certificate
- `server.cert_pin` is optional and can be used instead of a CA file
- `auth.machine_id` and `auth.token` must match a proxy-side `auth.clients` entry
- `local_proxy.auth_token` can protect the local CONNECT proxy with Basic auth if you need it
- `transparent.capture_host` controls interception for host-originated HTTPS traffic
- `transparent.capture_cidrs` lists source CIDRs on the same Linux host whose HTTPS traffic should also be redirected
- `transparent.exclude_cidrs` lists destination CIDRs that must bypass interception
- `transparent.exclude_pids` is a Windows-oriented manual override for extra WinDivert exclusions

## Running The Agent

### From a release package

```bash
./heimdall-local-agent run --config ./agent-config.yaml
```

### From a source build

```bash
target/release/heimdall-local-agent run --config config/agent-config.yaml
```

Or with Cargo:

```bash
cargo run --release -- run --config config/agent-config.yaml
```

## Useful Commands

```bash
heimdall-local-agent test --config config/agent-config.yaml
heimdall-local-agent status
heimdall-local-agent install --config config/agent-config.yaml --ca-cert /path/to/ca.crt
heimdall-local-agent uninstall
heimdall-local-agent service status
```

If your packaged release uses a shorter wrapper name such as `heimdall-agent`, the subcommands remain the same.

## Explicit Proxy Mode

Use this mode when you want per-process routing without changing the whole machine.

If you want a fuller walkthrough for non-transparent usage, including CI/CD and per-app wrapper patterns, see [Explicit Proxy Guide](explicit-proxy.md).

1. start the agent
2. point the application at `http://127.0.0.1:19080`
3. send placeholder tokens instead of real secrets

Example:

```bash
HTTPS_PROXY=http://127.0.0.1:19080 \
  curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

## Transparent Interception Mode

Transparent mode removes the need to configure `HTTPS_PROXY` per application.

Enable it in the config:

```yaml
transparent:
  enabled: true
  host: "0.0.0.0"
  port: 19443
  method: "auto"
  capture_host: true
  capture_cidrs:
    - "172.17.0.0/16"
  exclude_cidrs:
    - "10.0.0.0/8"
```

Then install Heimdall with elevated privileges:

```bash
heimdall-local-agent install \
  --config config/agent-config.yaml \
  --ca-cert /path/to/ca.crt
```

What `install` does:

- installs the Heimdall CA certificate into the local trust store unless `--no-cert` is used
- enables traffic interception unless `--no-interception` is used
- optionally installs a service when `--service` is provided

### Linux interception scopes

On Linux, transparent mode now supports two scopes on the same machine:

- host-process interception:
  - traffic originated directly by processes on the runner or workstation host
- runtime-network interception:
  - traffic whose source IP comes from configured local bridge or CNI subnets

This is meant for Linux workloads hosted on that machine, such as:

- Docker bridge networks
- Podman bridge networks
- local CNI-managed runtime subnets on the same host

It does not claim interception for:

- remote Kubernetes clusters
- external hosts
- traffic originating on a different machine

### Platform notes

- Windows:
  - `method: auto` tries WinDivert first and falls back to system proxy
  - `method: windivert` requires the packet interception path to be available
  - `method: system_proxy` is simpler but only affects apps that honor system proxy settings
- Linux:
  - transparent mode uses trust-store installation plus `iptables` and `ip6tables` redirect rules
  - host traffic is redirected from `nat OUTPUT`
  - configured runtime subnets are redirected from `nat PREROUTING`
  - the agent excludes its own host-side traffic by UID to avoid tunnel loops
  - elevated privileges are required for install and uninstall

## Service Management

Heimdall can also run as a background service.

```bash
heimdall-local-agent service install --config config/agent-config.yaml
heimdall-local-agent service start
heimdall-local-agent service status
heimdall-local-agent service stop
heimdall-local-agent service uninstall
```

For self-hosted CI or demo runners, prefer:

- a root-owned config file such as `/etc/heimdall/agent-config.yaml`
- `0600` permissions on that config file
- the GitHub runner itself running as a different unprivileged user

That keeps the runner user from reading the Heimdall setup directly while still letting the machine route HTTPS through the transparent listener.

## Health And Troubleshooting

The agent exposes a health endpoint on `http://127.0.0.1:19876/health` by default.

Useful checks:

- `heimdall-local-agent test --config ...` verifies tunnel connection and auth
- `heimdall-local-agent status` queries the health endpoint
- `heimdall-local-agent service status` reports service install state, including whether interception was configured during install
- if traffic is not tunneling, confirm the proxy server recognizes the `machine_id`
- if transparent mode is enabled but Linux host traffic bypasses Heimdall, test from a non-root shell with both `curl -4` and `curl -6`
- if runtime traffic bypasses Heimdall on Linux, confirm the runtime subnet appears in `transparent.capture_cidrs`
- if a destination must bypass interception, add its subnet to `transparent.exclude_cidrs`
- if transparent mode is enabled but apps are still bypassing Heimdall, confirm the chosen interception method is actually active on that OS

## Release Guidance

If you are publishing executables for teammates:

- ship per-platform archives instead of asking users to compile Rust
- include checksums in every release
- sign binaries if your distribution process supports it
- keep the packaged config template aligned with `config/agent-config.example.yaml`
- mention whether transparent mode is supported, experimental, or unsupported on each platform

## Related Docs

- [Explicit Proxy Guide](explicit-proxy.md)
- [Quick Start](quickstart.md)
- [Deployment Guide](deployment.md)
- [Architecture](architecture.md)
