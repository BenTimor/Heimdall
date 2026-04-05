# Guardian Local Agent Guide

This file applies to `local-agent/` and overrides the repository guide where needed.

## Purpose

The local agent runs on developer or workstation machines. It exposes a local CONNECT proxy, optionally intercepts HTTPS traffic transparently, and multiplexes traffic over a TLS tunnel to the Guardian proxy server.

## Primary Commands

```bash
cargo build --release
cargo test
cargo run -- run --config config/agent-config.yaml
cargo run -- test --config config/agent-config.yaml
cargo run -- status
cargo run -- install --config config/agent-config.yaml --ca-cert /path/to/guardian-ca.crt
cargo run -- uninstall
cargo run -- service status
```

## Source Map

- `src/main.rs` defines the CLI and install/service lifecycle commands
- `src/agent.rs` owns runtime startup, reconnect logic, and coordinated shutdown
- `src/config.rs` owns YAML config parsing and defaults
- `src/local_proxy.rs` owns explicit `HTTPS_PROXY` mode
- `src/transparent.rs` and `src/sni.rs` own transparent interception and SNI routing
- `src/tunnel/` owns TLS tunnel connection, framing, and multiplexing
- `src/platform/` owns platform-specific install, interception, certificate, and service behavior
- `tests/` covers protocol and SNI behavior

## Editing Rules

- Keep `src/config.rs`, `config/agent-config.example.yaml`, and the docs in sync.
- If you change tunnel frames or semantics, update `proxy-server` in the same change.
- If you change install, uninstall, service, or transparent-mode behavior, update `README.md` and `../docs/local-agent.md`.
- Be careful with platform-specific code paths:
  - Windows: system proxy, WinDivert, service management
  - Linux: iptables, trust store updates, systemd

## Release And Packaging Notes

- Source builds currently produce `target/release/guardian-local-agent`.
- Human-facing docs may refer to the packaged executable as the Guardian local agent, but commands and subcommands must stay aligned with the actual CLI.
- If release artifacts change shape, update the installation and release guidance in `README.md` and `../docs/local-agent.md`.

## Special Caution

- `windivert-sys-patched/` is a patched upstream dependency. Do not modify it during ordinary agent work.
- `target/` is build output and should not be treated as source.

## Verification

- Run `cargo test` after behavior changes.
- For tunnel changes, verify interoperability with the proxy server.
- For transparent interception changes, document any OS-specific caveats clearly.
