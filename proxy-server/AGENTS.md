# Guardian Proxy Server Agent Guide

This file applies to `proxy-server/` and overrides the repository guide where needed.

## Purpose

The proxy server is the central Guardian service. It authenticates clients and agents, terminates HTTPS for approved domains, injects secrets, forwards requests upstream, and optionally runs the tunnel server and admin panel.

## Primary Commands

```bash
pnpm install
pnpm run dev
pnpm run build
pnpm run lint
pnpm test
pnpm run generate-ca
pnpm run generate-tunnel-cert <hostname-or-ip>
```

## Source Map

- `src/index.ts` wires config, auth, secret providers, audit logging, proxy server, tunnel server, and panel startup
- `src/config/` owns the Zod schemas and YAML loading
- `src/proxy/` owns CONNECT handling, MITM, passthrough, certificate generation, OCSP, and upstream transport
- `src/tunnel/` owns the binary protocol, session manager, and TLS tunnel server
- `src/injection/` owns placeholder scanning and replacement
- `src/secrets/` owns provider integrations and caching
- `src/auth/` owns config-backed and DB-backed client authentication
- `src/panel/` owns the optional admin panel, SQLite access, and static frontend
- `tests/` contains unit and integration coverage

## Editing Rules

- Keep `src/config/schema.ts`, `config/server-config.example.yaml`, and the docs in sync.
- If you change tunnel frames or semantics, update the Rust agent implementation and both protocol test suites in the same change.
- If you change auth behavior, make sure both CONNECT proxy auth and tunnel auth still align.
- If you change panel capabilities or stored-secret behavior, update deployment docs and backup guidance.
- Treat `certs/`, `data/`, and `dist/` as runtime artifacts, not canonical sources.

## Verification

- Run `pnpm run lint` after code or config changes.
- Run `pnpm test` when behavior changes.
- For tunnel or MITM changes, verify both direct proxy and tunnel-backed flows.

## Operational Notes

- `proxy.publicHost` matters for OCSP responder URLs embedded in minted MITM certificates.
- Remote-agent deployments need both the MITM CA and a tunnel server certificate.
- The admin panel is opt-in and should default to localhost-only access.

