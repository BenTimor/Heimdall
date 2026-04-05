# Heimdall Explicit Proxy Guide

This guide covers Heimdall's non-transparent mode, where you route traffic explicitly with `HTTPS_PROXY` instead of changing machine-wide network behavior.

Use this mode when you want a narrower blast radius or when you control environment variables but not the full machine.

## Good Fits For Explicit Proxy Mode

- wrapping a specific CLI, desktop app, or script without affecting the whole workstation
- CI/CD pipelines where you can set env vars but cannot install system-wide interception rules
- containers or ephemeral environments where machine-wide install steps are undesirable
- Linux VPS or server environments where the workload runs as `root` or transparent interception is not the right fit
- phased rollouts where you want to validate Heimdall on a few commands before enabling transparent mode

## Two Variants

- explicit proxy through the local agent
  - best when you still want the authenticated tunnel and local workstation daemon
- explicit proxy directly to the proxy server
  - useful for CI jobs, single-machine setups, or environments where the local agent adds no value

## Option A: Explicit Proxy Through The Local Agent

This keeps the local-agent tunnel flow, but only for apps you explicitly wrap.

### 1. Prepare the proxy server

Set up the proxy server and tunnel server as described in [Quick Start](quickstart.md) or [Deployment Guide](deployment.md).

### 2. Configure the local agent

Start from `local-agent/config/agent-config.example.yaml` and leave transparent mode disabled:

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "/path/to/heimdall-ca.crt"

auth:
  machine_id: "dev-machine-01"
  token: "some-secure-token-here"

transparent:
  enabled: false
```

### 3. Make clients trust the Heimdall CA

Even in explicit proxy mode, Heimdall still performs MITM on approved domains, so clients must trust the Heimdall CA.

Choose one of these trust strategies:

- install the CA on the machine, but skip interception:

```bash
heimdall-local-agent install \
  --config config/agent-config.yaml \
  --ca-cert /path/to/heimdall-ca.crt \
  --no-interception
```

- or use per-tool trust overrides:
  - `curl --cacert /path/to/heimdall-ca.crt`
  - `REQUESTS_CA_BUNDLE=/path/to/heimdall-ca.crt`
  - `NODE_EXTRA_CA_CERTS=/path/to/heimdall-ca.crt`
  - `SSL_CERT_FILE=/path/to/heimdall-ca.crt`

The second approach is especially useful in CI/CD or locked-down environments.

### 4. Start the local agent

```bash
heimdall-local-agent run --config config/agent-config.yaml
```

Or from source:

```bash
cargo run --release -- run --config config/agent-config.yaml
```

### 5. Wrap specific commands or applications

Example one-shot command:

```bash
HTTPS_PROXY=http://127.0.0.1:19080 \
  curl --cacert /path/to/heimdall-ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

Example wrapper pattern:

```bash
HTTPS_PROXY=http://127.0.0.1:19080 your-command
```

This is a good fit when you want to wrap one tool, one shell session, one IDE launcher, or one integration test command.

## Option B: Explicit Proxy Directly To The Proxy Server

You can also skip the local agent and point `HTTPS_PROXY` straight at the Heimdall proxy server.

This is often the simplest model for:

- CI/CD runners
- ephemeral build containers
- single-machine evaluations
- environments where you control env vars but cannot run the local agent as a background process

### 1. Configure client auth

Use a proxy URL that includes the Heimdall `machineId` and `token`:

```bash
HTTPS_PROXY=http://machineId:token@proxy.example.com:8080
```

### 2. Provide CA trust per process

Examples:

```bash
HTTPS_PROXY=http://machineId:token@proxy.example.com:8080 \
  curl --cacert /path/to/heimdall-ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"
```

```bash
export HTTPS_PROXY=http://machineId:token@proxy.example.com:8080
export REQUESTS_CA_BUNDLE=/path/to/heimdall-ca.crt
```

This pattern works well when the environment is disposable and you only need env vars, not a machine-level install.

## Tradeoffs

Explicit proxy mode is usually easier to scope and easier to roll out gradually, but it has one important limitation: every participating process must be opted in.

Transparent mode is a better fit when your goal is "it just works" across the workstation after a one-time install.

## Related Docs

- [Quick Start](quickstart.md)
- [Deployment Guide](deployment.md)
- [Local Agent Guide](local-agent.md)
- [Architecture](architecture.md)
