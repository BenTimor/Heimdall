# Guardian Local Agent Guide

The local agent is the workstation-side entry point for Guardian. It gives developers a local proxy endpoint, can intercept HTTPS transparently, and forwards approved traffic to the proxy server over an authenticated TLS tunnel.

## Installation Options

### Option 1: Download a prebuilt executable

For end users, prebuilt releases are the preferred experience because they do not require a Rust toolchain.

When your team publishes binaries, distribute them from the repository's [GitHub Releases page](https://github.com/BenTimor/Heimdall/releases).

Recommended release contents:

- the platform binary:
  - `guardian-local-agent.exe` on Windows
  - `guardian-local-agent` on Linux
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

Source builds currently produce `target/release/guardian-local-agent`.

## Basic Configuration

Start from the example file:

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "/path/to/ca.crt"
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
  exclude_pids: []

logging:
  level: "info"
```

Notes:

- `server.host` and `server.port` point to the proxy server's tunnel listener.
- `server.ca_cert` is optional and should point at the CA that signed the tunnel server certificate.
- `server.cert_pin` is optional and can be used instead of a CA file.
- `auth.machine_id` and `auth.token` must match the proxy server's `auth.clients`.
- `local_proxy.auth_token` can protect the local CONNECT proxy with Basic auth if you need it.
- `transparent.exclude_pids` is an advanced Windows override for excluding extra processes from WinDivert interception.

## Running The Agent

### From a release package

```bash
./guardian-local-agent run --config ./agent-config.yaml
```

### From a source build

```bash
target/release/guardian-local-agent run --config config/agent-config.yaml
```

Or with Cargo:

```bash
cargo run --release -- run --config config/agent-config.yaml
```

## Useful Commands

```bash
guardian-local-agent test --config config/agent-config.yaml
guardian-local-agent status
guardian-local-agent install --config config/agent-config.yaml --ca-cert /path/to/ca.crt
guardian-local-agent uninstall
guardian-local-agent service status
```

If your packaged release uses a shorter wrapper name such as `guardian-agent`, the subcommands remain the same.

## Explicit Proxy Mode

Use this mode when you want per-process routing without changing the whole workstation.

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
```

Then install Guardian with elevated privileges:

```bash
guardian-local-agent install \
  --config config/agent-config.yaml \
  --ca-cert /path/to/ca.crt
```

What `install` does:

- installs the Guardian CA certificate into the local trust store unless `--no-cert` is used
- enables traffic interception unless `--no-interception` is used
- optionally installs a service when `--service` is provided

### Platform notes

- Windows:
  - `method: auto` tries WinDivert first and falls back to system proxy
  - `method: windivert` requires the packet interception path to be available
  - `method: system_proxy` is simpler but only affects apps that honor system proxy settings
- Linux:
  - transparent mode uses trust-store installation plus `iptables` redirection
  - elevated privileges are required for install and uninstall

## Service Management

Guardian can also run as a background service.

```bash
guardian-local-agent service install --config config/agent-config.yaml
guardian-local-agent service start
guardian-local-agent service status
guardian-local-agent service stop
guardian-local-agent service uninstall
```

For end-user release packages, document whether the installer wires this up automatically or leaves it as a manual step.

## Health And Troubleshooting

The agent exposes a health endpoint on `http://127.0.0.1:19876/health` by default.

Useful checks:

- `guardian-local-agent test --config ...` verifies tunnel connection and auth
- `guardian-local-agent status` queries the health endpoint
- if traffic is not tunneling, confirm the proxy server recognizes the `machine_id`
- if transparent mode is enabled but apps are bypassing Guardian, confirm the chosen interception method is actually active on that OS

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
