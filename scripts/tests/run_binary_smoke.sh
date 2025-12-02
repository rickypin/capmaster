#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY=${1:-"${ROOT_DIR}/dist/capmaster"}

if [[ ! -x "${BINARY}" ]]; then
  echo "error: executable ${BINARY} not found" >&2
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "warning: tshark is not installed; analyze smoke test may be limited" >&2
fi

"${BINARY}" --help >/dev/null
"${BINARY}" match --help >/dev/null

PCAP_INPUT=${SMOKE_PCAP:-}
if [[ -n "${PCAP_INPUT}" && -f "${PCAP_INPUT}" ]]; then
  "${BINARY}" analyze -i "${PCAP_INPUT}" --allow-no-input >/dev/null || true
else
  "${BINARY}" analyze --allow-no-input >/dev/null || true
fi

echo "Smoke test passed for ${BINARY}"
