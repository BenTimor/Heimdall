#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  echo "setup-heimdall currently supports Linux and macOS runners. Configure Windows trust and proxy env vars manually." >&2
  exit 1
fi

: "${INPUT_PROXY_URL:?INPUT_PROXY_URL is required}"
: "${INPUT_CA_CERT:?INPUT_CA_CERT is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

runner_temp="${RUNNER_TEMP:-$(mktemp -d)}"
heimdall_dir="${runner_temp}/heimdall"
mkdir -p "${heimdall_dir}"

ca_input="${INPUT_CA_CERT//$'\r'/}"
if [[ "${ca_input}" == *'\\n'* && "${ca_input}" != *$'\n'* ]]; then
  ca_input="${ca_input//\\n/$'\n'}"
fi

ca_cert_path="${heimdall_dir}/heimdall-ca.crt"
printf '%s\n' "${ca_input}" > "${ca_cert_path}"

if ! grep -q "BEGIN CERTIFICATE" "${ca_cert_path}"; then
  echo "The ca_cert input does not look like a PEM certificate." >&2
  exit 1
fi

find_base_bundle() {
  local candidate
  local -a candidates=()

  if [[ -n "${SSL_CERT_FILE:-}" ]]; then
    candidates+=("${SSL_CERT_FILE}")
  fi

  if [[ -n "${REQUESTS_CA_BUNDLE:-}" ]]; then
    candidates+=("${REQUESTS_CA_BUNDLE}")
  fi

  candidates+=(
    "/etc/ssl/certs/ca-certificates.crt"
    "/etc/pki/tls/certs/ca-bundle.crt"
    "/etc/ssl/cert.pem"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  if command -v python3 >/dev/null 2>&1; then
    candidate="$(
      python3 - <<'PY' 2>/dev/null || true
import sys
try:
    import certifi
except Exception:
    sys.exit(1)
sys.stdout.write(certifi.where())
PY
    )"
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  fi

  return 1
}

base_bundle_path="$(find_base_bundle || true)"
if [[ -z "${base_bundle_path}" ]]; then
  echo "Could not find a base CA bundle on this runner. Set SSL_CERT_FILE before calling setup-heimdall." >&2
  exit 1
fi

ca_bundle_path="${heimdall_dir}/ca-bundle.pem"
cat "${base_bundle_path}" > "${ca_bundle_path}"
printf '\n' >> "${ca_bundle_path}"
cat "${ca_cert_path}" >> "${ca_bundle_path}"

no_proxy_value="${INPUT_NO_PROXY}"
if [[ -n "${NO_PROXY:-}" ]]; then
  no_proxy_value="${no_proxy_value},${NO_PROXY}"
fi

{
  printf 'HEIMDALL_PROXY_URL=%s\n' "${INPUT_PROXY_URL}"
  printf 'HEIMDALL_CA_CERT_PATH=%s\n' "${ca_cert_path}"
  printf 'HEIMDALL_CA_BUNDLE_PATH=%s\n' "${ca_bundle_path}"
  printf 'HTTP_PROXY=%s\n' "${INPUT_PROXY_URL}"
  printf 'HTTPS_PROXY=%s\n' "${INPUT_PROXY_URL}"
  printf 'ALL_PROXY=%s\n' "${INPUT_PROXY_URL}"
  printf 'http_proxy=%s\n' "${INPUT_PROXY_URL}"
  printf 'https_proxy=%s\n' "${INPUT_PROXY_URL}"
  printf 'all_proxy=%s\n' "${INPUT_PROXY_URL}"
  printf 'NO_PROXY=%s\n' "${no_proxy_value}"
  printf 'no_proxy=%s\n' "${no_proxy_value}"
  printf 'NODE_EXTRA_CA_CERTS=%s\n' "${ca_cert_path}"
  printf 'SSL_CERT_FILE=%s\n' "${ca_bundle_path}"
  printf 'REQUESTS_CA_BUNDLE=%s\n' "${ca_bundle_path}"
  printf 'CURL_CA_BUNDLE=%s\n' "${ca_bundle_path}"
  printf 'GIT_SSL_CAINFO=%s\n' "${ca_bundle_path}"
  printf 'PIP_CERT=%s\n' "${ca_bundle_path}"
} >> "${GITHUB_ENV}"

{
  printf 'proxy_url=%s\n' "${INPUT_PROXY_URL}"
  printf 'ca_cert_path=%s\n' "${ca_cert_path}"
  printf 'ca_bundle_path=%s\n' "${ca_bundle_path}"
} >> "${GITHUB_OUTPUT}"

echo "Configured Heimdall proxy environment using base bundle ${base_bundle_path}."
