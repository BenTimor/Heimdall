# Guardian Local Agent

Lightweight Rust daemon that runs on developer machines and tunnels HTTPS traffic to a remote Guardian proxy server. The proxy injects real secrets into requests so they never exist on the developer's machine.

## How It Works

```
Your App                     Local Agent                    Proxy Server
   │                            │                               │
   │── CONNECT api.openai.com ─►│                               │
   │◄── 200 Established ───────│                               │
   │── TLS + HTTP request ────►│                               │
   │   "Bearer __OPENAI_KEY__" │── NEW_CONNECTION frame ──────►│
   │                            │── DATA frame (TLS bytes) ───►│ ── decrypts ──►
   │                            │                               │ ── injects key ──►
   │                            │                               │ ── forwards to API ──►
   │                            │◄── DATA frame (response) ────│
   │◄── response ──────────────│                               │
```

1. Applications set `HTTPS_PROXY=http://127.0.0.1:19080`
2. The agent accepts CONNECT requests and forwards them through a multiplexed TLS tunnel to the proxy server
3. The proxy performs MITM, injects secrets, and forwards to the real API
4. Responses flow back through the same tunnel

## Prerequisites

- **Rust 1.75+** (install from [rustup.rs](https://rustup.rs))
- A running Guardian proxy server with tunnel enabled

## Installation

### Build from source

```bash
cd local-agent
cargo build --release
```

The binary is at `target/release/guardian-local-agent` (or `guardian-local-agent.exe` on Windows).

## Configuration

Copy the example config and edit it:

```bash
cp config/agent-config.example.yaml config/agent-config.yaml
```

### Minimal config

```yaml
server:
  host: "proxy.yourcompany.com"
  port: 8443

auth:
  machine_id: "your-machine-id"
  token: "your-auth-token"
```

### Full config reference

```yaml
server:
  host: "proxy.yourcompany.com"   # Proxy server hostname
  port: 8443                       # Proxy tunnel port
  ca_cert: null                    # Path to custom CA cert (optional)

auth:
  machine_id: "dev-machine-01"     # Must match a client in proxy server config
  token: "secret-token"            # Must match the token for this machine_id

local_proxy:
  port: 19080                      # Local CONNECT proxy port (default: 19080)
  host: "127.0.0.1"               # Local bind address (default: 127.0.0.1)

health:
  port: 19876                      # Health endpoint port (default: 19876)
  host: "127.0.0.1"               # Health bind address (default: 127.0.0.1)

reconnect:
  initial_delay_ms: 1000           # First reconnect delay (default: 1000)
  max_delay_ms: 60000              # Maximum backoff delay (default: 60000)
  multiplier: 2.0                  # Exponential backoff multiplier (default: 2.0)

logging:
  level: "info"                    # trace, debug, info, warn, error (default: info)
```

### Server-side setup

The proxy server must have this machine registered as a client:

```yaml
# In proxy-server/config/server-config.yaml
auth:
  enabled: true
  clients:
    - machineId: "dev-machine-01"
      token: "secret-token"
```

And the tunnel server must be enabled (see proxy-server README).

## Usage

### Start the agent

```bash
# With default config path
guardian-local-agent run

# With custom config
guardian-local-agent run --config /path/to/config.yaml

# Or via cargo
cargo run --release -- run --config config/agent-config.yaml
```

You should see:

```
INFO connecting to tunnel server...
INFO tunnel authenticated successfully
INFO local CONNECT proxy listening addr=127.0.0.1:19080
INFO health endpoint listening addr=127.0.0.1:19876
INFO agent running proxy_addr=127.0.0.1:19080 health_addr=127.0.0.1:19876
```

### Test connectivity

Verify the agent can connect and authenticate with the proxy server:

```bash
guardian-local-agent test --config config/agent-config.yaml
```

### Check status

Query the running agent's health endpoint:

```bash
guardian-local-agent status

# Or with a custom URL
guardian-local-agent status --url http://127.0.0.1:19876
```

Returns JSON:

```json
{
  "status": "ok",
  "machine_id": "dev-machine-01",
  "tunnel_uptime_secs": 3600,
  "active_connections": 2,
  "last_heartbeat_secs_ago": 5
}
```

### Use with your application

Point any HTTP client at the local agent:

```bash
# curl
HTTPS_PROXY=http://127.0.0.1:19080 \
  curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer __OPENAI_API_KEY__"

# Python
import os
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:19080"

# Node.js
# Set HTTPS_PROXY=http://127.0.0.1:19080 in your environment

# Any language/framework that respects HTTPS_PROXY
```

## Running Tests

```bash
cargo test
```

25 tests covering the binary tunnel protocol (roundtrip encoding, partial frame delivery, cross-language hex fixtures).

## Project Structure

```
local-agent/
  src/
    main.rs                 # CLI entry point (run, test, status)
    agent.rs                # Orchestrator: connect tunnel, start proxy + health
    config.rs               # YAML config deserialization
    local_proxy.rs          # HTTP CONNECT proxy on localhost:19080
    health.rs               # Axum health endpoint on localhost:19876
    lib.rs                  # Public module exports
    tunnel/
      mod.rs                # Module declarations
      protocol.rs           # Binary frame codec (FrameType, Frame, FrameCodec)
      client.rs             # TLS tunnel connect + auth + reconnect
      multiplexer.rs        # Connection multiplexing + heartbeat
  tests/
    protocol_test.rs        # Protocol unit tests + cross-language fixtures
  config/
    agent-config.example.yaml
  Cargo.toml
```

## Reconnection

The agent automatically reconnects to the proxy server with exponential backoff if the tunnel drops. Configure the behavior in the `reconnect` section of the config:

- Starts at `initial_delay_ms` (default 1s)
- Multiplies by `multiplier` (default 2x) each attempt
- Caps at `max_delay_ms` (default 60s)
- Resets to initial delay on successful reconnection

## Graceful Shutdown

Press `Ctrl+C` to shut down. The agent will:

1. Signal all tasks to stop
2. Close the local proxy listener
3. Stop the health endpoint
4. Close the tunnel connection

## License

MIT
