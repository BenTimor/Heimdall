# Security Hardening Backlog

Tracked security improvements for Phase 7. Items are roughly prioritized.

## To Implement Now

- [ ] **Credential zeroization** — Use `zeroize` crate to scrub auth tokens from memory after use. Wrap `auth.token` and the formatted AUTH payload in `Zeroizing<String>`. Prevents token recovery from core dumps, swap, or hibernation files.
- [ ] **TLS certificate pinning** — Add `server.cert_pin: "sha256/..."` config option. Validate server cert public key hash in tunnel client's `build_tls_config()`. Prevents MITM on the agent-to-proxy tunnel if a CA is compromised.
- [ ] **Tunnel connection limits** — Add `max_connections_per_session` config (default 1000) to both `SessionManager` (proxy) and `Multiplexer` (agent). Reject new connections above the limit with a CLOSE frame.
- [ ] **Streaming body passthrough** — Refactor HTTP parser so only headers are buffered in memory. Pipe body bytes directly from source to destination socket without buffering. Prevents OOM from large request bodies.
- [ ] **Placeholder replaceAll** — Change `injector.ts:72` from `.replace()` to `.replaceAll()` so all placeholder occurrences in a header are injected, not just the first.
- [ ] **Local CONNECT proxy auth** — Require `Proxy-Authorization` header on the local proxy (port 19080). Prevents arbitrary local processes from tunneling through the agent.
- [ ] **State file permissions** — Set 0600 (Unix) / restrictive DACL (Windows) on install state file after writing. Contains CA cert paths and original env var values.
- [ ] **Health endpoint: remove machine_id** — Remove `machine_id` from the `/health` JSON response. Leaks agent identity to anyone who can reach port 19876.
- [ ] **Auth-disabled warning** — Log a prominent WARN at proxy server startup when `auth.enabled: false`. Prevents accidental auth bypass.
- [ ] **Graceful connection drain on shutdown** — Send CLOSE frames to active connections before stopping multiplexer. Wait up to 30s for drain, then force-close.
- [ ] **Linux iptables rules lost on reboot** — When the agent starts as a systemd service (`run` command), it does NOT re-apply iptables rules from `install`. Transparent interception silently breaks after reboot. Fix: check and re-apply rules on agent startup if state file indicates interception was installed.
- [ ] **Migrate serde_yaml to serde_yml** — `serde_yaml` is deprecated and won't receive fixes. `serde_yml` is MIT/Apache-2.0 (same license), drop-in replacement.
- [ ] **Install cargo-audit** — Add `cargo audit` to CI pipeline for ongoing Rust dependency vulnerability scanning.
- [ ] **Update transitive dependencies** — Bump `@aws-sdk/client-secrets-manager` (fixes `fast-xml-parser` stack overflow in `preserveOrder` — unreachable in practice but good hygiene). Bump `vitest` (fixes `esbuild` dev server CORS — dev-only, not production).

## Backlog (Future)

- [ ] **Rate limiting** — Add per-IP / per-machineId token bucket rate limiter to: CONNECT requests on proxy server, transparent listener (agent), OCSP responder (proxy), health endpoint (agent). Start with CONNECT and transparent listener.
- [ ] **Audit logger resilience** — Current `audit-logger.ts` silently ignores `writeSync()` failures (disk full, permission denied). Should catch errors and log to stderr. Don't fail requests — add proper structured logging mechanism first, then make audit logging reliable on top of it.
- [ ] **Certificate expiry monitoring** — MITM CA certs have 1-year validity. No warning when approaching expiry — it fails silently. Need a notification mechanism beyond logs (since no one regularly watches them). Consider: health endpoint warning field, CLI `status` command warning, or push notification to a monitoring channel.
- [ ] **Config hot-reload** — Currently requires service restart for credential rotation or config changes, causing traffic loss. Plan: build a proper management panel with live config updates. Signal-based reload (SIGHUP) is an interim option but the panel is the real solution.
- [ ] **WinDivert NAT table soft warning** — Log a warning if NAT table exceeds 10,000 entries. Don't drop connections (legitimate machines can be busy). Hard limit at 100,000 as OOM safety net.
- [ ] **SNI parser fuzz testing** — Parser is solid but add fuzz tests for confidence. Cap hostname at 253 bytes (DNS max). Use `cargo-fuzz` or `arbitrary` crate.
- [ ] **Env var credential source** — Support `GUARDIAN_TOKEN` / `GUARDIAN_MACHINE_ID` env vars as alternative to YAML config. Useful for CI/CD and secret management tool integration.
