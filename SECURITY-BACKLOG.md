# Security Hardening Backlog

Tracked security improvements for Phase 7. Items are roughly prioritized.

## Backlog (Future)

- [ ] **Rate limiting** — Add per-IP / per-machineId token bucket rate limiter to: CONNECT requests on proxy server, transparent listener (agent), OCSP responder (proxy), health endpoint (agent). Start with CONNECT and transparent listener.
- [ ] **Audit logger resilience** — Current `audit-logger.ts` silently ignores `writeSync()` failures (disk full, permission denied). Should catch errors and log to stderr. Don't fail requests — add proper structured logging mechanism first, then make audit logging reliable on top of it.
- [ ] **Certificate expiry monitoring** — MITM CA certs have 1-year validity. No warning when approaching expiry — it fails silently. Need a notification mechanism beyond logs (since no one regularly watches them). Consider: health endpoint warning field, CLI `status` command warning, or push notification to a monitoring channel.
- [ ] **Config hot-reload** — Currently requires service restart for credential rotation or config changes, causing traffic loss. Plan: build a proper management panel with live config updates. Signal-based reload (SIGHUP) is an interim option but the panel is the real solution.
- [ ] **WinDivert NAT table soft warning** — Log a warning if NAT table exceeds 10,000 entries. Don't drop connections (legitimate machines can be busy). Hard limit at 100,000 as OOM safety net.
- [ ] **SNI parser fuzz testing** — Parser is solid but add fuzz tests for confidence. Cap hostname at 253 bytes (DNS max). Use `cargo-fuzz` or `arbitrary` crate.
- [ ] **Env var credential source** — Support `GUARDIAN_TOKEN` / `GUARDIAN_MACHINE_ID` env vars as alternative to YAML config. Useful for CI/CD and secret management tool integration.
