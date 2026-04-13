# Heimdall In GitHub Actions

This guide shows how to use Heimdall placeholders in GitHub Actions without storing the real upstream API secrets in GitHub.

For the public `opencode` demo, the recommended path is now an ephemeral self-hosted Linux runner with Heimdall preinstalled on the host in transparent mode. The workflow keeps using the upstream OpenCode GitHub Action, but the Heimdall client credential lives only on the disposable runner host, not in GitHub secrets or workflow environment variables.

## Short Version

- public demo or security-sensitive showcase:
  - use an ephemeral self-hosted Linux runner
  - install Heimdall on the runner host as a root-owned service
  - enable transparent interception on the host
  - allowlist the runner egress IP or CIDR on the Heimdall server with `sourceCidrs`
  - keep `OPENROUTER_API_KEY` and similar values as placeholders in the workflow
- ordinary GitHub-hosted runner usage:
  - run the local agent inside the job
  - keep transparent mode disabled
  - export `HTTPS_PROXY` to the local agent
- direct proxy to the Heimdall server:
  - only for private self-hosted networks where the proxy hop is already transport-protected

## Recommended Topology For The Public Demo

The public demo should use this model:

1. build a dedicated Linux runner image
2. install the GitHub runner as an unprivileged user such as `gha-runner`
3. install Heimdall as a host service owned by `root` or a dedicated `heimdall` user
4. store the Heimdall config at `/etc/heimdall/agent-config.yaml` with `0600` permissions
5. install the Heimdall CA into the machine trust store during image build or first boot
6. enable transparent interception before the runner accepts jobs
7. register the runner as ephemeral so it handles one job and is then destroyed

This keeps the upstream OpenCode action unchanged while moving the reusable Heimdall credential out of GitHub and into a disposable machine boundary.

The repository's own [`opencode` workflow](../.github/workflows/opencode.yml) now follows this shape:

- `runs-on` points at a self-hosted runner label
- the workflow only checks that the host-side Heimdall service is healthy
- the workflow does not build or configure Heimdall inside the job
- the workflow does not export `HTTP_PROXY` or `HTTPS_PROXY`
- the workflow passes a placeholder `OPENROUTER_API_KEY` directly to the upstream OpenCode action

## Server-Side Hardening Checklist

For the demo deployment:

- use a dedicated Heimdall deployment, or at minimum a dedicated demo-only secret scope
- keep per-secret `allowedDomains` restrictions enabled
- create a dedicated demo client entry under `auth.clients`
- set `sourceCidrs` on that client to the runner's fixed public egress IP or private CIDR
- enable the tunnel listener if the local agent connects through the tunnel

Example:

```yaml
auth:
  enabled: true
  clients:
    - machineId: "github-actions-opencode-demo"
      token: "replace-with-a-long-random-token"
      sourceCidrs:
        - "203.0.113.10/32"
```

What `sourceCidrs` protects:

- if the demo credential leaks into logs or model output, it only works from the allowed runner network
- the same policy applies to direct proxy auth and tunnel auth

What it does not protect:

- a job already running on the runner can still use the demo-scoped credential during that run
- this is why the demo should use isolated, low-value secrets and a disposable runner

## Runner Image Provisioning

Recommended image contents:

- GitHub Actions runner installed as `gha-runner`
- Heimdall local agent binary installed on the host
- systemd service for Heimdall enabled at boot
- `/etc/heimdall/agent-config.yaml` owned by `root:root` with `0600`
- Heimdall MITM CA installed into the OS trust store
- transparent interception installed before the runner process starts accepting jobs

Recommended local-agent config for the host service:

```yaml
server:
  host: "proxy.example.com"
  port: 8443
  ca_cert: "/etc/heimdall/tunnel-ca.crt"

auth:
  machine_id: "github-actions-opencode-demo"
  token: "replace-with-the-demo-token"

local_proxy:
  host: "127.0.0.1"
  port: 19080

health:
  host: "127.0.0.1"
  port: 19876

transparent:
  enabled: true
  host: "0.0.0.0"
  port: 19443
  method: "auto"
  capture_host: true
  capture_cidrs: []
  exclude_cidrs: []

logging:
  level: "info"
```

If the runner also launches Docker, Podman, or CNI-based workloads on the same machine, add those bridge subnets to `transparent.capture_cidrs`.

Examples:

- Docker default bridge: `172.17.0.0/16`
- Podman rootful bridge: often `10.88.0.0/16`
- custom CNI bridge ranges: whatever your runner host allocates locally

Keep `transparent.exclude_cidrs` for destination networks that must bypass interception.

If you want a ready-made starting point for a fresh Ubuntu x64 VPS, this repository now includes:

- [`scripts/demo-runner/bootstrap-ubuntu-runner.sh`](../scripts/demo-runner/bootstrap-ubuntu-runner.sh)
- [`scripts/demo-runner/example.env`](../scripts/demo-runner/example.env)

That helper script provisions the runner host only. It does not deploy the Heimdall proxy server itself.

## Workflow Example For The Self-Hosted Transparent Demo

```yaml
name: opencode

on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
    types: [created]

jobs:
  opencode:
    runs-on:
      - self-hosted
      - linux
      - x64
      - heimdall-demo
    permissions:
      contents: read
      pull-requests: read
      issues: read

    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false

      - name: Validate host Heimdall service
        run: curl --silent --fail http://127.0.0.1:19876/health > /dev/null

      - name: Run opencode
        uses: anomalyco/opencode/github@latest
        env:
          OPENROUTER_API_KEY: __OPENROUTER_API_KEY__
        with:
          model: openrouter/z-ai/glm-5.1
```

Important differences from the older GitHub-hosted setup:

- no `HEIMDALL_TOKEN` secret in GitHub
- no `HEIMDALL_MACHINE_ID` variable in GitHub
- no `HEIMDALL_TUNNEL_HOST`, `HEIMDALL_TUNNEL_PORT`, or `HEIMDALL_CA_CERT` in the workflow
- no `id-token: write` permission when you are not using GitHub OIDC bootstrap
- no `setup-heimdall` action step
- no `HTTP_PROXY` or `HTTPS_PROXY` export in the workflow

## Ephemeral Runner Requirement

Use GitHub's ephemeral self-hosted runner lifecycle for the public demo.

That means:

- one runner VM accepts one job
- after the job, destroy the VM
- do not reuse the workspace or Heimdall runtime state for the next demo run

Why this matters:

- it limits the lifetime of any leaked demo-scoped material
- it prevents cross-job persistence in workspaces, logs, or temp files
- it lets you keep the upstream OpenCode action unchanged while still enforcing strong host isolation

## Linux Transparent Scope

On self-hosted Linux, Heimdall transparent mode now supports two interception scopes on the same host:

- host-process interception for traffic created by the runner host itself
- runtime-network interception for traffic whose source IP comes from configured local bridge or CNI subnets

This is the intended v1 support boundary:

- host processes on the runner
- Docker, Podman, or other Linux runtimes that use bridge or CNI subnets on that same runner host

This guide does not claim off-host interception for:

- remote Kubernetes clusters
- separate container hosts
- arbitrary external networks

## Fallback: GitHub-Hosted Runners

If you need to run on `ubuntu-latest` or another GitHub-hosted runner, use explicit proxy mode through the local agent inside the job.

That fallback still works well for ordinary users because:

- the tunnel hop is TLS-protected
- placeholders still keep the real upstream secret out of GitHub
- the setup does not require self-hosted infrastructure

The tradeoff is that the Heimdall client credential must exist in workflow scope for the duration of that job, so it is not the recommended path for the public demo.

See [Explicit Proxy Guide](explicit-proxy.md) for the explicit-proxy flow and [Local Agent Guide](local-agent.md) for the agent configuration details.
