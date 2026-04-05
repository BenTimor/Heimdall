# Heimdall Local Agent

The local agent runs on developer machines. It exposes a local CONNECT proxy, can intercept HTTPS traffic transparently, and forwards approved traffic to the Heimdall proxy server over an authenticated TLS tunnel.

Project site: [heimdall.co.il](https://heimdall.co.il)

## Installation

### Download a release package

For end users, prebuilt binaries are the preferred path when your team publishes them.

- use the repository's [GitHub Releases page](https://github.com/BenTimor/Heimdall/releases)
- prefer release archives over asking developers to install Rust
- include checksums and platform support notes with every release

### Build from source

```bash
cd local-agent
cargo build --release
cp config/agent-config.example.yaml config/agent-config.yaml
```

Source builds currently produce `target/release/heimdall-local-agent`.

## Minimal Configuration

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "/path/to/ca.crt"

auth:
  machine_id: "dev-machine-01"
  token: "replace-me"
```

The proxy server must have a matching client entry in `proxy-server/config/server-config.yaml`.

## Start The Agent

### From a source build

```bash
target/release/heimdall-local-agent run --config config/agent-config.yaml
```

### With Cargo

```bash
cargo run --release -- run --config config/agent-config.yaml
```

Useful companion commands:

```bash
target/release/heimdall-local-agent test --config config/agent-config.yaml
target/release/heimdall-local-agent status
```

If your packaged release uses a shorter wrapper name such as `heimdall-agent`, the same subcommands apply.

## Use It

### Explicit proxy mode

Point your application at the local agent:

```bash
HTTPS_PROXY=http://127.0.0.1:19080 \
  curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

For per-app wrappers, CI/CD usage, and other non-transparent patterns, see [../docs/explicit-proxy.md](../docs/explicit-proxy.md).

### Transparent mode

Enable transparent interception in the config:

```yaml
transparent:
  enabled: true
  host: "0.0.0.0"
  port: 19443
  method: "auto"
```

Then install Heimdall with elevated privileges so the CA certificate and interception rules can be applied:

```bash
cargo run --release -- install \
  --config config/agent-config.yaml \
  --ca-cert /path/to/heimdall-ca.crt
```

Windows supports `auto`, `windivert`, and `system_proxy`. Linux uses trust-store installation plus `iptables` and `ip6tables` redirection to the transparent TLS listener for approved IPv4 and IPv6 HTTPS traffic.

For Linux server or VPS validation, prefer explicit proxy mode first if the workload runs as `root` or you want a narrower smoke test surface.

## Service Management

```bash
cargo run -- service install --config config/agent-config.yaml
cargo run -- service start
cargo run -- service status
cargo run -- service stop
cargo run -- service uninstall
```

## Development

```bash
cargo test
cargo build --release
```

## More Documentation

- [Local Agent Guide](../docs/local-agent.md)
- [Explicit Proxy Guide](../docs/explicit-proxy.md)
- [Quick Start](../docs/quickstart.md)
- [Architecture](../docs/architecture.md)
- [Repository README](../README.md)
