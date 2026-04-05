# Guardian Agent Guide

This file is the canonical repository-wide guide for AI coding agents and automation tools.

## Scope

- Applies to the entire repository unless a deeper `AGENTS.md` overrides it.
- Component-specific guidance lives in:
  - `proxy-server/AGENTS.md`
  - `local-agent/AGENTS.md`

## Repository Overview

Guardian keeps live API secrets off developer machines.

- `proxy-server/` is the control plane and data plane:
  - authenticates clients and tunnel sessions
  - performs HTTPS MITM for approved domains
  - resolves secrets from environment variables, AWS Secrets Manager, or stored panel-managed secrets
  - exposes the optional admin panel, audit logging, and tunnel server
- `local-agent/` is the developer-side daemon:
  - provides a local `HTTPS_PROXY` endpoint
  - optionally intercepts HTTPS traffic transparently
  - multiplexes proxied traffic over a TLS tunnel to the proxy server
- `docs/` holds the operator-facing documentation set
- `README.md` is the primary landing page for humans

## Working Agreements

- Treat `AGENTS.md` files as the canonical machine-oriented guidance.
- Treat `CLAUDE.md` files as compatibility shims that point back to `AGENTS.md`.
- Keep documentation aligned with the code:
  - update `README.md`, `docs/`, and config examples when commands, config fields, or workflows change
  - update both sides of any cross-language protocol change
- Prefer editing first-party source and docs only.
- Avoid modifying runtime or generated directories unless the task explicitly requires it:
  - `proxy-server/node_modules/`
  - `proxy-server/dist/`
  - `proxy-server/data/`
  - `local-agent/target/`
- `local-agent/windivert-sys-patched/` is a patched third-party dependency. Only change it when the task is specifically about the WinDivert patch or build behavior.

## Common Commands

### Proxy server

```bash
cd proxy-server
pnpm install
pnpm run dev
pnpm run build
pnpm run lint
pnpm test
pnpm run generate-ca
pnpm run generate-tunnel-cert <hostname-or-ip>
```

### Local agent

```bash
cd local-agent
cargo build --release
cargo test
cargo run -- run --config config/agent-config.yaml
cargo run -- test --config config/agent-config.yaml
cargo run -- status
cargo run -- install --config config/agent-config.yaml --ca-cert /path/to/guardian-ca.crt
cargo run -- uninstall
```

## Cross-Component Contracts

- Authentication:
  - proxy and tunnel auth both use the same `machineId` and `token` pair
  - `local-agent.auth.machine_id` and `local-agent.auth.token` must match a proxy-side client entry
- Tunnel protocol:
  - implemented in both `proxy-server/src/tunnel/protocol.ts` and `local-agent/src/tunnel/protocol.rs`
  - update both sides together
- Connection routing:
  - the server sends the domain list after auth
  - the agent tunnels only matching domains and bypasses the rest directly
- Secret injection:
  - placeholders are replaced only for configured secrets and allowed domains

## Documentation Responsibilities

- `README.md` should stay concise, trustworthy, and release-friendly.
- `docs/quickstart.md` should remain the fastest path to a working setup.
- `docs/deployment.md` should cover production-oriented server setup and operations.
- `docs/local-agent.md` should cover installation, release artifacts, service mode, and transparent interception.
- `docs/architecture.md` should explain the system and cross-component flow without code-level noise.

## When To Update Docs

Update docs in the same change when you modify any of the following:

- CLI commands or flags
- config schema or example config files
- installation or release packaging flow
- trust model, auth flow, or tunnel protocol
- admin panel capabilities
- platform support or transparent interception behavior
