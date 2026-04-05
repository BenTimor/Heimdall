# Plan: Full client-facing HTTP/2 MITM and clearer latency logs

## Context
- Guardian’s low-risk latency fixes are already in place, and the latest logs show proxy CPU work is no longer the bottleneck.
- Current proxy logs show very small `headerParseMs`, `secretResolveMs`, and `auditMs`, while the largest remaining bucket is `waitForRequestMs` on the decrypted client-facing side.
- The current MITM path only speaks client-facing HTTP/1.1 after TLS termination, so clients that would normally multiplex over HTTP/2 are likely being downgraded onto multiple parallel H1 connections.
- Goal: add full client-facing HTTP/2 support on the MITM side while keeping secrets server-side only, preserving HTTP/1.1 fallback, and improving logs so “waiting for the client” is clearly separated from “active proxy work”.

## Approach
- Optimize the client-facing side first because current logs suggest that is where the biggest remaining win is, but include upstream HTTP/2 in the same implementation pass once requests are normalized.
- Recommended implementation shape:
  1. advertise `h2` + `http/1.1` during the MITM TLS handshake,
  2. branch on negotiated ALPN after TLS setup,
  3. keep the existing H1 parser/loop for `http/1.1`,
  4. add a new H2 request path that accepts streams, normalizes headers, performs injection, and writes the response back on the same H2 stream,
  5. refactor upstream forwarding around a protocol-neutral request/response shape so the proxy can choose H2 upstream when the origin supports it, with fallback to the existing H1/TLS pool.
- Recommendation on upstream H2: yes, include it. The code exploration shows it is not totally free, because the current pool is H1-socket-specific, but once the forwarding path is normalized for client H2 anyway, adding an H2 upstream transport and ALPN fallback is a sensible incremental step rather than a separate project.
- Logging recommendation for this phase: keep current timing fields for continuity, but add clearer canonical protocol-aware fields (`clientProtocol`, `upstreamProtocol`, stream identifiers, and active-handling timing that excludes passive client wait). That gives better analysis without making before/after comparisons harder.

## Files to modify
- `proxy-server/src/proxy/mitm.ts`
- `proxy-server/src/proxy/server.ts`
- `proxy-server/src/proxy/http-parser.ts` (H1 fallback helpers / shared body-stream utilities)
- `proxy-server/src/proxy/connection-pool.ts` (shared hooks for H1 fallback and clearer transport split, if needed)
- `proxy-server/src/proxy/upstream-http2-pool.ts` (new; dedicated reusable H2 session management)
- `proxy-server/tests/integration/proxy-e2e.test.ts`
- `proxy-server/tests/integration/proxy-hardening.test.ts`
- `proxy-server/tests/integration/tunnel-e2e.test.ts`
- `proxy-server/README.md`
- `proxy-server/CLAUDE.md`
- `CLAUDE.md`

## Reuse
- `proxy-server/src/proxy/mitm.ts`
  - existing TLS MITM setup, request timing logs, secret injection call site, and upstream forwarding path.
- `proxy-server/src/proxy/http-parser.ts`
  - existing H1 header parsing and body piping utilities for the fallback path, plus reusable body-stream patterns that can be generalized for H2 streams.
- `proxy-server/src/injection/injector.ts`
  - existing header-injection logic works on a normalized header map and should be reused for H2 after pseudo-header filtering/translation.
- `proxy-server/src/proxy/connection-pool.ts`
  - existing warm H1 upstream reuse is already performant; it should remain the H1 fallback transport rather than being stretched to manage H2 sessions.
- Node built-in `node:http2`
  - `performServerHandshake()` is available in the current Node runtime and should allow attaching an HTTP/2 server session to the already-secured MITM `TLSSocket`.
  - `http2.connect()` / `ClientHttp2Session.request()` can provide upstream H2 transport once request forwarding is normalized.

## Findings so far
- `proxy-server/src/proxy/mitm.ts` currently wraps the client socket in `new tls.TLSSocket(..., { isServer: true, cert, key })`, then always runs `parseHttpHeaders()` in a loop, so the decrypted client-facing side is H1-only today.
- Current MITM timing logs already emit request-level fields such as `waitForRequestMs`, `headerParseMs`, `parseMs`, `upstreamPoolReused`, and `upstreamResponseHeaderMs`.
- The main forwarding path (`forwardToTarget`) already streams request bodies and response bodies, but it currently assumes a raw serialized H1 request line/headers buffer plus an H1-oriented `SocketReader` body source.
- `injectSecrets()` expects ordinary header name/value pairs, so H2 support will need explicit handling for pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) before and after injection.
- `proxy-server/src/proxy/connection-pool.ts` is specifically built around reusable idle `tls.TLSSocket`s and TLS session tickets; it is a good H1 fallback pool but not the right abstraction for multiplexed H2 upstream sessions. Upstream H2 should therefore use a separate small session manager/pool rather than overloading the existing one.
- Because full client H2 already requires normalizing requests away from raw H1 bytes, upstream H2 becomes much easier to add in the same refactor than it would be in the current pre-refactor shape.

## Steps
- [x] Confirm the exact HTTP/2 server integration point on top of the existing MITM `TLSSocket`, then factor `handleMitm()` into protocol-specific client handlers plus shared request-processing helpers.
- [x] Add ALPN negotiation for `h2` and `http/1.1` on the client-facing MITM TLS handshake and preserve current H1 fallback behavior.
- [x] Introduce a normalized internal request/response forwarding shape so both H1 and H2 client paths can share injection, auditing, body streaming, and timing logic.
- [x] Implement the client-facing H2 stream handler: normalize request metadata/headers, read request bodies from the H2 stream, reuse secret injection, forward upstream, and translate upstream responses back into H2 headers/body frames.
- [x] Add upstream H2 transport with its own reusable session manager/pool, use ALPN to prefer H2 when available, and fall back cleanly to the existing H1/TLS `ConnectionPool` when the origin does not negotiate H2 or the H2 path fails.
- [x] Extend latency logs with protocol-aware fields (at minimum negotiated client ALPN, upstream protocol, and per-stream identifiers) and add an additive “active handling” timing that excludes passive waiting for the client.
- [x] Add H2 integration coverage for explicit proxy / tunnel MITM paths plus upstream-H2/fallback cases while keeping all existing H1 tests green.
- [x] Update docs with the new client-facing protocol behavior, upstream protocol selection behavior, log fields, and verification guidance.

## Verification
- Explicit proxy mode:
  - H1 client still works unchanged.
  - H2-capable client negotiates `h2` through the MITM path and receives correct injected headers / responses.
  - Origins that support H2 are forwarded over upstream H2; origins that do not still succeed over H1 fallback.
- Tunnel mode:
  - existing agent/tunnel path still reaches MITM correctly and client-facing H2 works over the tunneled TLS stream.
- Logging:
  - request logs show negotiated client protocol, upstream protocol selection, and clearer timing split between waiting and active handling.
- Tests:
  - `cd proxy-server && pnpm run lint`
  - `cd proxy-server && pnpm test`
- Manual benchmark:
  - rerun the same latency benchmark and compare warm proxied requests before/after, focusing on fewer parallel same-origin connections, active-request timings, and whether warm upstream H2 reduces reconnect churn further.

## Resolved scope decisions
- Scope stays limited to **standard HTTP request/response only** for this phase.
- Explicitly out of scope for now: **gRPC**, **extended CONNECT**, and **WebSocket-over-H2**.
- Logging will use the recommended transition model for this phase: keep current fields for continuity, but add clearer canonical H2-aware fields so future analysis is easier.