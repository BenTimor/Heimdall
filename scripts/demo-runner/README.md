# Demo Runner Bootstrap

This directory contains a bootstrap script for the public-demo self-hosted runner design.

The script is intended for:

- a fresh Ubuntu x64 VPS
- full root access
- systemd available
- Heimdall proxy server already deployed elsewhere

It installs:

- the Heimdall local agent as a root-owned host service
- the Heimdall CA into the machine trust store
- Linux transparent interception on the runner host
- a GitHub self-hosted runner as the unprivileged `gha-runner` user
- a GitHub self-hosted runner registration tied to your repository or org
- cleanup hooks that wipe the runner workdir and OpenCode state between jobs

## Usage

1. Copy `example.env` and fill in the placeholders.
2. Source it on the VPS.
3. Run:

```bash
sudo -E bash ./scripts/demo-runner/bootstrap-ubuntu-runner.sh
```

## Important

- This script provisions the runner host only.
- It does not deploy the Heimdall proxy server.
- The runner stays online and keeps picking up jobs automatically.
