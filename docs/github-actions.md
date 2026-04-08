# Heimdall In GitHub Actions

This guide shows how to use Heimdall placeholders in GitHub Actions without storing the real upstream API secrets in GitHub.

The short version:

- GitHub-hosted runners should use the Heimdall local agent in explicit proxy mode so traffic reaches the server over the existing TLS tunnel.
- self-hosted runners on a private network can point `HTTPS_PROXY` straight at the Heimdall proxy server if that connection is already transport-protected by your network design
- in both cases, your workflow can keep using placeholder values such as `__OPENAI_API_KEY__`

## Choose The Right Topology

### GitHub-hosted runners

Use this when your jobs run on `ubuntu-latest`, `ubuntu-24.04`, or other GitHub-hosted machines.

Recommended path:

1. start `heimdall-local-agent` inside the job
2. keep `transparent.enabled: false`
3. point the job at `http://127.0.0.1:19080`
4. let the local agent tunnel matching traffic to the Heimdall server over TLS

Why this is the recommended path:

- the tunnel link is already TLS-protected
- the proxy auth token does not travel over the public internet in a plain HTTP proxy request
- the rest of the job can still use ordinary `HTTPS_PROXY` semantics

### Self-hosted runners on a private network

Use this when the runner and the Heimdall proxy server already communicate over a trusted path such as:

- the same VPC or subnet
- a private VPN
- an internal load balancer or other transport-protected network edge

In that case you can skip the local agent and point the job directly at the Heimdall proxy listener.

Do not use the direct `http://machineId:token@proxy.example.com:8080` pattern from a public GitHub-hosted runner unless you have separately protected that proxy hop. Heimdall's built-in direct proxy listener is an HTTP CONNECT proxy, not a TLS listener.

## Server-Side Checklist

For GitHub-hosted runners:

- enable the Heimdall tunnel server
- set `proxy.publicHost` to the hostname clients can actually reach
- generate the tunnel certificate with `pnpm run generate-tunnel-cert <hostname-or-ip>`
- create a dedicated `auth.clients` entry for each GitHub environment or workflow scope
- make sure the real upstream secrets exist on the Heimdall server through `env`, AWS Secrets Manager, or stored secrets

Example `auth.clients` entries:

```yaml
auth:
  enabled: true
  clients:
    - machineId: "github-actions-myrepo-staging"
      token: "replace-with-a-long-random-token"
    - machineId: "github-actions-myrepo-production"
      token: "replace-with-a-different-token"
```

Recommended naming pattern:

- one `machineId` per repository and environment
- rotate tokens independently
- disable or delete only the affected entry if one workflow scope is compromised

## GitHub-Side Values

Store these in GitHub Actions secrets or environment-scoped secrets:

- `HEIMDALL_CA_CERT`: the Heimdall MITM CA certificate in PEM format
- `HEIMDALL_TOKEN`: the auth token that matches the selected `machineId`

Store these as variables or environment-scoped variables:

- `HEIMDALL_TUNNEL_HOST`: the public hostname of the Heimdall tunnel listener
- `HEIMDALL_TUNNEL_PORT`: usually `8443`
- `HEIMDALL_MACHINE_ID`: for example `github-actions-myrepo-staging`

If you use the simpler direct-proxy model on a private self-hosted runner, store:

- `HEIMDALL_PROXY_URL`: for example `http://machineId:token@proxy.internal.example.com:8080`
- `HEIMDALL_CA_CERT`: the Heimdall CA PEM

If the direct proxy URL contains special characters in the credentials, percent-encode them before saving the URL.

## Reusable Runner Setup Action

This repository now includes a small reusable action at `.github/actions/setup-heimdall/`.

Use it in one of these ways:

- inside this repository: `uses: ./.github/actions/setup-heimdall`
- from another repository: `uses: BenTimor/Heimdall/.github/actions/setup-heimdall@<tag-or-commit>`

Prefer a pinned tag or commit SHA instead of `@main` in production workflows.

It:

- writes the Heimdall CA to the runner
- creates a merged CA bundle for OpenSSL-based tools
- exports `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase equivalents
- exports `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, and `PIP_CERT`

That is enough for most `curl`, Node.js, Python, Git, and Go workloads.

If you run JVM-based tools, add the Heimdall CA to a Java truststore separately. The action does not mutate Java's `cacerts`.

## Recommended Workflow For GitHub-Hosted Ubuntu Runners

This example builds the local agent from source in the job. If you publish a Linux release artifact, you can replace the build step with a download step.

The repository's own [`opencode` workflow](../.github/workflows/opencode.yml) now follows this same pattern: it starts the local agent, exports the Heimdall proxy env, and then runs the upstream `opencode` GitHub Action with your placeholder-valued `OPENROUTER_API_KEY`.

```yaml
name: heimdall-example

on:
  workflow_dispatch:

jobs:
  placeholder-smoke-test:
    runs-on: ubuntu-latest
    environment: staging

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build Heimdall local agent
        run: cargo build --release --manifest-path local-agent/Cargo.toml

      - name: Write Heimdall agent config
        shell: bash
        run: |
          cat > "$RUNNER_TEMP/heimdall-agent.yaml" <<EOF
          server:
            host: "${{ vars.HEIMDALL_TUNNEL_HOST }}"
            port: ${{ vars.HEIMDALL_TUNNEL_PORT }}
            ca_cert: "$RUNNER_TEMP/heimdall-ca.crt"

          auth:
            machine_id: "${{ vars.HEIMDALL_MACHINE_ID }}"
            token: "${{ secrets.HEIMDALL_TOKEN }}"

          local_proxy:
            host: "127.0.0.1"
            port: 19080

          health:
            host: "127.0.0.1"
            port: 19876

          transparent:
            enabled: false

          logging:
            level: "info"
          EOF

      - name: Write Heimdall CA
        shell: bash
        run: |
          printf '%s\n' "${{ secrets.HEIMDALL_CA_CERT }}" > "$RUNNER_TEMP/heimdall-ca.crt"

      - name: Start Heimdall local agent
        shell: bash
        run: |
          nohup ./local-agent/target/release/heimdall-local-agent \
            run \
            --config "$RUNNER_TEMP/heimdall-agent.yaml" \
            > "$RUNNER_TEMP/heimdall-agent.log" 2>&1 &
          echo $! > "$RUNNER_TEMP/heimdall-agent.pid"

      - name: Wait for Heimdall local proxy
        shell: bash
        run: |
          for attempt in $(seq 1 30); do
            if curl --silent --fail http://127.0.0.1:19876/health > /dev/null; then
              exit 0
            fi
            sleep 1
          done
          cat "$RUNNER_TEMP/heimdall-agent.log" || true
          exit 1

      - name: Verify tunnel auth
        shell: bash
        run: |
          ./local-agent/target/release/heimdall-local-agent \
            test \
            --config "$RUNNER_TEMP/heimdall-agent.yaml"

      - name: Export Heimdall proxy env
        uses: BenTimor/Heimdall/.github/actions/setup-heimdall@main
        with:
          proxy_url: http://127.0.0.1:19080
          ca_cert: ${{ secrets.HEIMDALL_CA_CERT }}

      - name: Smoke test a placeholder
        env:
          OPENAI_API_KEY: __OPENAI_API_KEY__
        run: |
          curl https://api.openai.com/v1/models \
            -H "Authorization: Bearer ${OPENAI_API_KEY}"

      - name: Run your real workload with placeholders
        env:
          OPENAI_API_KEY: __OPENAI_API_KEY__
          ANTHROPIC_API_KEY: __ANTHROPIC_API_KEY__
        run: |
          npm ci
          npm test

      - name: Print Heimdall agent log on failure
        if: failure()
        shell: bash
        run: cat "$RUNNER_TEMP/heimdall-agent.log" || true

      - name: Stop Heimdall local agent
        if: always()
        shell: bash
        run: |
          if [ -f "$RUNNER_TEMP/heimdall-agent.pid" ]; then
            kill "$(cat "$RUNNER_TEMP/heimdall-agent.pid")" || true
          fi
```

Notes:

- the example uses `OPENAI_API_KEY=__OPENAI_API_KEY__`; the actual secret remains only on the Heimdall server
- any SDK or CLI that turns that placeholder into an outbound HTTP header can work unchanged
- non-secret domains still pass through Heimdall without MITM because no secret is configured for them

## Simpler Workflow For Private Self-Hosted Runners

If your runner already reaches the Heimdall proxy listener through a trusted internal path, you can skip the local agent:

```yaml
name: heimdall-direct-example

on:
  workflow_dispatch:

jobs:
  placeholder-smoke-test:
    runs-on: self-hosted

    steps:
      - uses: actions/checkout@v4

      - name: Export Heimdall proxy env
        uses: BenTimor/Heimdall/.github/actions/setup-heimdall@main
        with:
          proxy_url: ${{ secrets.HEIMDALL_PROXY_URL }}
          ca_cert: ${{ secrets.HEIMDALL_CA_CERT }}

      - name: Run with placeholders
        env:
          OPENAI_API_KEY: __OPENAI_API_KEY__
        run: |
          curl https://api.openai.com/v1/models \
            -H "Authorization: Bearer ${OPENAI_API_KEY}"
```

This path is operationally simpler, but only use it when the runner-to-proxy hop is already private or otherwise protected.

## What Placeholders Can Replace

Heimdall currently injects placeholders that appear in outbound HTTP headers.

That means GitHub Actions works well when:

- a tool reads `OPENAI_API_KEY=__OPENAI_API_KEY__` and sends it as `Authorization: Bearer __OPENAI_API_KEY__`
- a script sends headers such as `X-Api-Key: __SERVICE_API_KEY__`

It does not replace placeholders in arbitrary request bodies, files, or local shell variables that never become outbound headers.

## Related Docs

- [Explicit Proxy Guide](explicit-proxy.md)
- [Deployment Guide](deployment.md)
- [Local Agent Guide](local-agent.md)
- [Architecture](architecture.md)
