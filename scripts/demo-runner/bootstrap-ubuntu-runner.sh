#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '\n==> %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run this script as root"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "missing required environment variable: ${name}"
}

lower_bool() {
  local value="${1:-}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    true|false) printf '%s' "$value" ;;
    1|yes|y) printf 'true' ;;
    0|no|n) printf 'false' ;;
    *) die "expected a boolean value, got: ${1}" ;;
  esac
}

csv_to_json_array() {
  python3 - "$1" <<'PY'
import json
import sys

raw = sys.argv[1].strip()
items = [item.strip() for item in raw.split(",") if item.strip()] if raw else []
print(json.dumps(items))
PY
}

json_array_to_yaml_block() {
  python3 - "$1" <<'PY'
import json
import sys

items = json.loads(sys.argv[1])
if not items:
    print("    []")
else:
    for item in items:
        escaped = item.replace('"', '\\"')
        print(f'    - "{escaped}"')
PY
}

parse_runner_scope() {
  python3 - "${GITHUB_RUNNER_URL}" <<'PY'
import sys
from urllib.parse import urlparse

url = urlparse(sys.argv[1])
if url.scheme != "https" or url.netloc not in {"github.com", "www.github.com"}:
    raise SystemExit("GITHUB_RUNNER_URL must be a https://github.com/... URL")

parts = [p for p in url.path.split("/") if p]
if len(parts) == 1:
    print(f"orgs/{parts[0]}/actions/runners/registration-token")
elif len(parts) == 2:
    print(f"repos/{parts[0]}/{parts[1]}/actions/runners/registration-token")
else:
    raise SystemExit("GITHUB_RUNNER_URL must point to an org or repository")
PY
}

fetch_runner_registration_token() {
  local endpoint
  endpoint="$(parse_runner_scope)"

  curl --fail --silent --show-error \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${GITHUB_PAT}" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/${endpoint}" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
token = data.get("token")
if not token:
    raise SystemExit("GitHub API response did not include a runner token")
print(token)
'
}

fetch_latest_runner_version() {
  curl --fail --silent --show-error \
    "https://api.github.com/repos/actions/runner/releases/latest" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
tag = data.get("tag_name", "")
if not tag.startswith("v"):
    raise SystemExit("Could not determine latest GitHub Actions runner version")
print(tag[1:])
'
}

write_pem_file() {
  local destination="$1"
  local pem_var="$2"
  local pem_b64_var="$3"

  if [[ -n "${!pem_b64_var:-}" ]]; then
    printf '%s' "${!pem_b64_var}" | base64 -d >"${destination}"
  elif [[ -n "${!pem_var:-}" ]]; then
    printf '%s\n' "${!pem_var}" >"${destination}"
  else
    die "missing certificate input for ${destination}; set ${pem_var} or ${pem_b64_var}"
  fi
  chmod 0600 "${destination}"
}

install_packages() {
  log "Installing system packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    ca-certificates \
    curl \
    git \
    iptables \
    iproute2 \
    libssl-dev \
    pkg-config \
    python3 \
    python3-venv \
    tar \
    build-essential
}

install_rust() {
  if [[ -x "/root/.cargo/bin/cargo" ]]; then
    export PATH="/root/.cargo/bin:${PATH}"
    return
  fi

  log "Installing Rust toolchain"
  curl --fail --silent --show-error https://sh.rustup.rs | sh -s -- -y --profile minimal
  export PATH="/root/.cargo/bin:${PATH}"
}

ensure_users() {
  if ! id -u "${RUNNER_USER}" >/dev/null 2>&1; then
    log "Creating ${RUNNER_USER} user"
    useradd --create-home --home-dir "${RUNNER_HOME}" --shell /bin/bash "${RUNNER_USER}"
  fi
}

build_local_agent() {
  log "Building Heimdall local agent"
  rm -rf "${HEIMDALL_SRC_DIR}"
  git clone --depth 1 --branch "${HEIMDALL_GIT_REF}" "${HEIMDALL_GIT_URL}" "${HEIMDALL_SRC_DIR}"
  (
    cd "${HEIMDALL_SRC_DIR}"
    cargo build --release --manifest-path local-agent/Cargo.toml
  )
  install -m 0755 "${HEIMDALL_SRC_DIR}/local-agent/target/release/heimdall-local-agent" /usr/local/bin/heimdall-local-agent
}

write_heimdall_config() {
  local tunnel_ca_path="${HEIMDALL_CONFIG_DIR}/tunnel-ca.crt"
  local mitm_ca_path="${HEIMDALL_CONFIG_DIR}/heimdall-ca.crt"
  local config_path="${HEIMDALL_CONFIG_DIR}/agent-config.yaml"

  mkdir -p "${HEIMDALL_CONFIG_DIR}"
  chmod 0700 "${HEIMDALL_CONFIG_DIR}"

  if [[ -n "${HEIMDALL_MITM_CA_CERT_PEM:-}" || -n "${HEIMDALL_MITM_CA_CERT_PEM_B64:-}" ]]; then
    write_pem_file "${mitm_ca_path}" HEIMDALL_MITM_CA_CERT_PEM HEIMDALL_MITM_CA_CERT_PEM_B64
  else
    write_pem_file "${mitm_ca_path}" HEIMDALL_TUNNEL_CA_CERT_PEM HEIMDALL_TUNNEL_CA_CERT_PEM_B64
  fi

  if [[ -n "${HEIMDALL_TUNNEL_CA_CERT_PEM:-}" || -n "${HEIMDALL_TUNNEL_CA_CERT_PEM_B64:-}" ]]; then
    write_pem_file "${tunnel_ca_path}" HEIMDALL_TUNNEL_CA_CERT_PEM HEIMDALL_TUNNEL_CA_CERT_PEM_B64
  else
    cp "${mitm_ca_path}" "${tunnel_ca_path}"
    chmod 0600 "${tunnel_ca_path}"
  fi

  local capture_host_yaml
  capture_host_yaml="$(lower_bool "${HEIMDALL_CAPTURE_HOST}")"
  local capture_cidrs_json
  capture_cidrs_json="$(csv_to_json_array "${HEIMDALL_CAPTURE_CIDRS}")"
  local exclude_cidrs_json
  exclude_cidrs_json="$(csv_to_json_array "${HEIMDALL_EXCLUDE_CIDRS}")"

  cat >"${config_path}" <<EOF
server:
  host: "${HEIMDALL_TUNNEL_HOST}"
  port: ${HEIMDALL_TUNNEL_PORT}
  ca_cert: "${tunnel_ca_path}"
  cert_pin: null

auth:
  machine_id: "${HEIMDALL_MACHINE_ID}"
  token: "${HEIMDALL_TOKEN}"

local_proxy:
  host: "127.0.0.1"
  port: 19080
  auth_token: null

health:
  host: "127.0.0.1"
  port: 19876

reconnect:
  initial_delay_ms: 1000
  max_delay_ms: 60000
  multiplier: 2.0

transparent:
  enabled: true
  host: "0.0.0.0"
  port: 19443
  method: "auto"
  capture_host: ${capture_host_yaml}
  capture_cidrs:
$(json_array_to_yaml_block "${capture_cidrs_json}")
  exclude_cidrs:
$(json_array_to_yaml_block "${exclude_cidrs_json}")
  exclude_pids: []

logging:
  level: "${HEIMDALL_LOG_LEVEL}"
EOF

  chmod 0600 "${config_path}"
}

install_heimdall_service() {
  log "Testing Heimdall tunnel connectivity"
  /usr/local/bin/heimdall-local-agent test --config "${HEIMDALL_CONFIG_DIR}/agent-config.yaml"

  log "Installing Heimdall transparent interception and service"
  /usr/local/bin/heimdall-local-agent install \
    --config "${HEIMDALL_CONFIG_DIR}/agent-config.yaml" \
    --ca-cert "${HEIMDALL_CONFIG_DIR}/heimdall-ca.crt" \
    --service

  log "Waiting for Heimdall health endpoint"
  for _ in $(seq 1 30); do
    if curl --silent --fail "http://127.0.0.1:19876/health" >/dev/null; then
      return
    fi
    sleep 1
  done
  die "Heimdall service did not become healthy on 127.0.0.1:19876"
}

install_runner() {
  local runner_version="${GITHUB_RUNNER_VERSION}"
  if [[ -z "${runner_version}" ]]; then
    log "Fetching latest GitHub Actions runner version"
    runner_version="$(fetch_latest_runner_version)"
  fi

  local runner_archive="actions-runner-linux-x64-${runner_version}.tar.gz"
  local runner_download_url="https://github.com/actions/runner/releases/download/v${runner_version}/${runner_archive}"
  local runner_tmp="/tmp/${runner_archive}"

  log "Installing GitHub Actions runner ${runner_version}"
  mkdir -p "${RUNNER_DIR}"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_HOME}"

  curl --fail --silent --show-error --location "${runner_download_url}" -o "${runner_tmp}"
  find "${RUNNER_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  tar -xzf "${runner_tmp}" -C "${RUNNER_DIR}"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_DIR}"

  local runner_token="${GITHUB_RUNNER_TOKEN}"
  if [[ -z "${runner_token}" ]]; then
    require_env GITHUB_PAT
    log "Fetching short-lived runner registration token from GitHub"
    runner_token="$(fetch_runner_registration_token)"
  fi

  local labels_arg=""
  if [[ -n "${GITHUB_RUNNER_LABELS}" ]]; then
    labels_arg="--labels ${GITHUB_RUNNER_LABELS}"
  fi

  local group_arg=""
  if [[ -n "${GITHUB_RUNNER_GROUP:-}" ]]; then
    group_arg="--runnergroup ${GITHUB_RUNNER_GROUP}"
  fi

  log "Registering runner against ${GITHUB_RUNNER_URL}"
  runuser -u "${RUNNER_USER}" -- bash -lc "
    cd '${RUNNER_DIR}'
    ./config.sh \
      --unattended \
      --replace \
      --url '${GITHUB_RUNNER_URL}' \
      --token '${runner_token}' \
      --name '${GITHUB_RUNNER_NAME}' \
      --work '${GITHUB_RUNNER_WORKDIR}' \
      ${labels_arg} \
      ${group_arg}
  "
}

install_runner_hooks() {
  if [[ "$(lower_bool "${GITHUB_RUNNER_ENABLE_HOOKS}")" != "true" ]]; then
    return
  fi

  log "Installing runner cleanup hooks"
  mkdir -p "${RUNNER_HOOKS_DIR}"

  cat >"${RUNNER_HOOKS_DIR}/job-started.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

cleanup_dir_contents() {
  local dir="\$1"
  if [[ -d "\${dir}" ]]; then
    find "\${dir}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  fi
}

cleanup_dir_contents "${RUNNER_USER_HOME}/.local/share/opencode"
cleanup_dir_contents "${RUNNER_USER_HOME}/.cache/opencode"
EOF

  cat >"${RUNNER_HOOKS_DIR}/job-completed.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

cleanup_runner_workdir() {
  local dir="\$1"
  if [[ -d "\${dir}" ]]; then
    find "\${dir}" -mindepth 1 -maxdepth 1 \
      ! -name '_actions' \
      ! -name '_tool' \
      ! -name '_temp' \
      ! -name '_diag' \
      -exec rm -rf {} +
  fi
}

cleanup_dir_contents() {
  local dir="\$1"
  if [[ -d "\${dir}" ]]; then
    find "\${dir}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  fi
}

cleanup_runner_workdir "${RUNNER_DIR}/${GITHUB_RUNNER_WORKDIR}"
cleanup_dir_contents "${RUNNER_USER_HOME}/.local/share/opencode"
cleanup_dir_contents "${RUNNER_USER_HOME}/.cache/opencode"
EOF

  chmod 0755 "${RUNNER_HOOKS_DIR}/job-started.sh" "${RUNNER_HOOKS_DIR}/job-completed.sh"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_HOOKS_DIR}"

  local runner_env="${RUNNER_DIR}/.env"
  if [[ -f "${runner_env}" ]]; then
    grep -v '^ACTIONS_RUNNER_HOOK_JOB_STARTED=' "${runner_env}" | \
      grep -v '^ACTIONS_RUNNER_HOOK_JOB_COMPLETED=' >"${runner_env}.tmp" || true
  else
    : >"${runner_env}.tmp"
  fi
  cat >>"${runner_env}.tmp" <<EOF
ACTIONS_RUNNER_HOOK_JOB_STARTED=${RUNNER_HOOKS_DIR}/job-started.sh
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=${RUNNER_HOOKS_DIR}/job-completed.sh
EOF
  mv "${runner_env}.tmp" "${runner_env}"

  chown "${RUNNER_USER}:${RUNNER_USER}" "${runner_env}"
  chmod 0644 "${runner_env}"
}

install_runner_service() {
  log "Installing GitHub runner systemd service"

  cat >/etc/systemd/system/github-actions-runner.service <<EOF
[Unit]
Description=GitHub Actions Runner
After=network-online.target heimdall-agent.service
Wants=network-online.target heimdall-agent.service
Requires=heimdall-agent.service

[Service]
Type=simple
User=${RUNNER_USER}
Group=${RUNNER_USER}
WorkingDirectory=${RUNNER_DIR}
ExecStart=${RUNNER_DIR}/run.sh
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable github-actions-runner.service
  systemctl restart github-actions-runner.service
}

print_summary() {
  cat <<EOF

Bootstrap complete.

Runner host:
  - GitHub runner service: github-actions-runner.service
  - Heimdall service: heimdall-agent
  - Heimdall config: ${HEIMDALL_CONFIG_DIR}/agent-config.yaml
  - Runner directory: ${RUNNER_DIR}
  - Runner labels: ${GITHUB_RUNNER_LABELS:-<default labels only>}

Next steps:
  1. Add ${HEIMDALL_RUNNER_SOURCE_CIDR_HINT} to the matching proxy-side auth.clients[].sourceCidrs allowlist.
  2. Make sure your workflow uses:
       runs-on: [self-hosted, linux, x64, heimdall-demo]

This script only provisions the runner host.
It does not deploy the Heimdall proxy server itself.
EOF
}

main() {
  require_root

  require_env GITHUB_RUNNER_URL
  require_env HEIMDALL_TUNNEL_HOST
  require_env HEIMDALL_MACHINE_ID
  require_env HEIMDALL_TOKEN

  if [[ -z "${GITHUB_RUNNER_TOKEN:-}" ]]; then
    require_env GITHUB_PAT
  fi

  if [[ -z "${HEIMDALL_TUNNEL_CA_CERT_PEM:-}" && -z "${HEIMDALL_TUNNEL_CA_CERT_PEM_B64:-}" && -z "${HEIMDALL_MITM_CA_CERT_PEM:-}" && -z "${HEIMDALL_MITM_CA_CERT_PEM_B64:-}" ]]; then
    die "set at least one certificate input: HEIMDALL_TUNNEL_CA_CERT_PEM(_B64) or HEIMDALL_MITM_CA_CERT_PEM(_B64)"
  fi

  install_packages
  require_command curl
  require_command python3
  require_command git
  install_rust
  ensure_users
  build_local_agent
  write_heimdall_config
  install_heimdall_service
  install_runner
  install_runner_hooks
  install_runner_service
  print_summary
}

RUNNER_USER="${RUNNER_USER:-gha-runner}"
RUNNER_USER_HOME="${RUNNER_USER_HOME:-/home/${RUNNER_USER}}"
RUNNER_HOME="${RUNNER_HOME:-/home/${RUNNER_USER}}"
RUNNER_DIR="${RUNNER_DIR:-/opt/actions-runner}"
RUNNER_HOOKS_DIR="${RUNNER_HOOKS_DIR:-${RUNNER_DIR}/hooks}"
GITHUB_RUNNER_NAME="${GITHUB_RUNNER_NAME:-$(hostname)-$(date +%Y%m%d%H%M%S)}"
GITHUB_RUNNER_LABELS="${GITHUB_RUNNER_LABELS:-heimdall-demo}"
GITHUB_RUNNER_WORKDIR="${GITHUB_RUNNER_WORKDIR:-_work}"
GITHUB_RUNNER_VERSION="${GITHUB_RUNNER_VERSION:-}"
GITHUB_RUNNER_ENABLE_HOOKS="${GITHUB_RUNNER_ENABLE_HOOKS:-true}"
HEIMDALL_GIT_URL="${HEIMDALL_GIT_URL:-https://github.com/BenTimor/Heimdall.git}"
HEIMDALL_GIT_REF="${HEIMDALL_GIT_REF:-main}"
HEIMDALL_SRC_DIR="${HEIMDALL_SRC_DIR:-/opt/heimdall-src}"
HEIMDALL_CONFIG_DIR="${HEIMDALL_CONFIG_DIR:-/etc/heimdall}"
HEIMDALL_TUNNEL_PORT="${HEIMDALL_TUNNEL_PORT:-8443}"
HEIMDALL_LOG_LEVEL="${HEIMDALL_LOG_LEVEL:-info}"
HEIMDALL_CAPTURE_HOST="${HEIMDALL_CAPTURE_HOST:-true}"
HEIMDALL_CAPTURE_CIDRS="${HEIMDALL_CAPTURE_CIDRS:-}"
HEIMDALL_EXCLUDE_CIDRS="${HEIMDALL_EXCLUDE_CIDRS:-}"
HEIMDALL_RUNNER_SOURCE_CIDR_HINT="${HEIMDALL_RUNNER_SOURCE_CIDR_HINT:-<runner-public-ip>/32}"
GITHUB_RUNNER_TOKEN="${GITHUB_RUNNER_TOKEN:-}"

main "$@"
