# Guardian

Guardian keeps live API secrets off developer machines.

Applications send placeholders such as `__OPENAI_API_KEY__`; Guardian intercepts approved HTTPS traffic, resolves the real secret on a controlled server, injects it only for allowed domains, and forwards the request upstream.

## Why Guardian

- centralize secret ownership instead of distributing live keys to laptops and CI runners
- support both explicit `HTTPS_PROXY` routing and transparent HTTPS interception
- enforce per-secret domain allow-lists to reduce exfiltration risk
- support environment variables, AWS Secrets Manager, and stored panel-managed secrets
- provide an optional admin panel, audit logging, and remote developer access through a TLS tunnel

## Components

| Component | Language | Responsibility |
| --- | --- | --- |
| [proxy-server/](proxy-server/) | Node.js / TypeScript | Authenticates clients and agents, performs MITM, resolves secrets, injects placeholders, serves the tunnel, and hosts the optional admin panel |
| [local-agent/](local-agent/) | Rust | Runs on developer machines, exposes a local proxy, optionally intercepts HTTPS transparently, and tunnels matching traffic to the server |

## Quick Start

The recommended first run is the transparent local-agent flow:

1. Set up the proxy server and tunnel listener.
2. Copy the Guardian CA certificate to the developer machine.
3. Configure the local agent with `transparent.enabled: true`.
4. Run `guardian-local-agent install --ca-cert /path/to/guardian-ca.crt`.
5. Start the agent and verify that apps work without setting `HTTPS_PROXY`.

Follow [docs/quickstart.md](docs/quickstart.md) for the full transparent walkthrough.
If you want per-process routing instead, see [docs/explicit-proxy.md](docs/explicit-proxy.md).

## Local-Agent Downloads

The Rust local agent is designed to be distributed as downloadable executables so developers do not need Rust installed.

- prefer the repository's [GitHub Releases page](https://github.com/BenTimor/Heimdall/releases) when prebuilt archives are published
- fall back to building from source only when you need a custom build
- see [local-agent/README.md](local-agent/README.md) and [docs/local-agent.md](docs/local-agent.md) for install and packaging guidance

## Documentation

- [Documentation Index](docs/README.md)
- [Quick Start](docs/quickstart.md)
- [Explicit Proxy Guide](docs/explicit-proxy.md)
- [Deployment Guide](docs/deployment.md)
- [Local Agent Guide](docs/local-agent.md)
- [Architecture](docs/architecture.md)

## How It Works

Guardian supports three practical usage modes:

- local-only mode
  - point `HTTPS_PROXY` straight at the proxy server
  - useful for smoke tests and single-machine setups
- explicit proxy mode
  - point apps at the local agent on `127.0.0.1:19080`
  - the agent forwards approved traffic through the authenticated tunnel
- transparent mode
  - install the local agent with elevated privileges
  - the agent intercepts outbound HTTPS traffic without per-app proxy configuration

In all cases, secrets are resolved and injected on the server side, not on the client machine.

## Production Notes

- set `proxy.publicHost` when the proxy is reachable from other machines so minted certificates contain a usable OCSP responder URL
- generate a dedicated tunnel certificate with `pnpm run generate-tunnel-cert <hostname-or-ip>` for remote agents
- keep `certs/`, `config/`, and `data/` out of version control and back them up appropriately
- keep the admin panel on localhost unless you have a deliberate access layer in front of it
- review [BACKLOG.md](BACKLOG.md) for remaining hardening work before a broad production rollout

## Repository Layout

- [proxy-server/](proxy-server/) contains the central HTTPS proxy and admin panel
- [local-agent/](local-agent/) contains the Rust workstation agent
- [docs/](docs/) contains deeper setup and operations documentation
- [AGENTS.md](AGENTS.md) contains the canonical machine-oriented contributor guide
