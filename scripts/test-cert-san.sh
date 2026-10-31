#!/usr/bin/env bash
# Regression test: self-signed certificates include an IP SAN.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$HERE")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-cert-san-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tls" "$WORK/app"
printf 'SSL_KEYFILE=%s/tls/privkey.pem\nSSL_CERTFILE=%s/tls/fullchain.pem\n' "$WORK" "$WORK" > "$WORK/app/.env"
APP_DIR="$WORK/app" TLS_REGENERATE=1 bash -c '. "'"$ROOT_DIR"'/lib.sh"; generate_selfsigned' >/dev/null 2>&1
openssl x509 -in "$WORK/tls/fullchain.pem" -noout -text | grep -q "IP Address:"
echo "ok: self-signed certificate includes an IP SAN"
