#!/usr/bin/env bash
# Regression test: install-result.env carries connection details for automation.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$HERE")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-setup-info-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/data" "$WORK/tls"
printf 'cert' > "$WORK/tls/fullchain.pem"
OVN_NAME=testnode OVN_PORT=2083 OVN_VPN_PORTS=1194 OVN_PROTO=udp OVN_TLS=selfsigned \
OVN_TLS_CERT="$WORK/tls/fullchain.pem" OVN_KEY=secretkey OVN_APP_DIR="$WORK/app" OVN_DATA_BASE="$WORK/data" \
  bash -c '. "'"$ROOT_DIR"'/lib.sh"; . "'"$ROOT_DIR"'/install.sh"; write_install_result "'"$WORK"'/data/install-result.env"' >/dev/null 2>&1
for key in OVNODE_ADDRESS OVNODE_PROTOCOL OVNODE_API_KEY OVNODE_CERT_FILE; do
    grep -q "^${key}=" "$WORK/data/install-result.env" || { echo "missing $key"; cat "$WORK/data/install-result.env"; exit 1; }
done
echo "ok: setup info persisted for automation"
