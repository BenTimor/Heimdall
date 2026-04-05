# Guardian Documentation

This directory contains the operator-facing documentation for Guardian.

## Start Here

- [Quick Start](quickstart.md): the recommended transparent local-agent onboarding flow
- [Explicit Proxy Guide](explicit-proxy.md): non-transparent per-process routing for wrapped apps, CI/CD, and controlled environments
- [Deployment Guide](deployment.md): how to run the proxy server in a team or production-like environment
- [Local Agent Guide](local-agent.md): installation, downloadable executables, transparent interception, and service management
- [Architecture](architecture.md): how the proxy server, local agent, and tunnel fit together

## Reading Paths

- Evaluating the project for the first time:
  - start with `../README.md`
  - then follow [Quick Start](quickstart.md)
- Evaluating non-transparent usage:
  - read [Explicit Proxy Guide](explicit-proxy.md)
- Rolling it out for a team:
  - read [Deployment Guide](deployment.md)
  - then share [Local Agent Guide](local-agent.md) with developers
- Changing the code:
  - use `../AGENTS.md`
  - then use the component-specific `AGENTS.md` in `../proxy-server/` or `../local-agent/`
