#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Duplicate function check: shared shell functions exist exactly once.
echo "=== duplicate function check ==="
# Extract function names from lib.sh
lib_funcs=$(grep -oE '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' lib.sh | tr -d '()' | sort -u)
dupes=""
for f in install.sh ovnode.sh; do
    for fn in $lib_funcs; do
        if grep -qE "^${fn}\(\)" "$f"; then
            dupes="$dupes $fn (in $f)"
        fi
    done
done
if [ -n "$dupes" ]; then
    echo "FAIL: lib.sh functions redefined elsewhere:$dupes"
    exit 1
fi
echo "OK: no duplicate function definitions"

# bash -n check
echo "=== bash -n check ==="
for f in install.sh ovnode.sh lib.sh; do
    bash -n "$f" || { echo "FAIL: $f"; exit 1; }
done
echo "OK: all shell files pass bash -n"

# Version parity
echo "=== version parity ==="
v_install=$(grep -m1 '^VERSION=' install.sh | cut -d= -f2 | tr -d '"')
v_ovnode=$(grep -m1 '^VERSION=' ovnode.sh | cut -d= -f2 | tr -d '"')
v_binary=$(go run ./cmd/ovnode version 2>/dev/null || echo "unknown")
echo "install.sh: $v_install"
echo "ovnode.sh:  $v_ovnode"
echo "binary:     $v_binary"
if [ "$v_install" != "$v_ovnode" ] || [ "$v_install" != "$v_binary" ]; then
    echo "FAIL: version mismatch"
    exit 1
fi
echo "OK: versions match"

# ── setup info persistence ─────────────────────────────────────────────
echo "=== setup info ==="
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-setup-info-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/data" "$WORK/tls"
printf 'cert' > "$WORK/tls/fullchain.pem"
OVN_NAME=testnode OVN_PORT=2083 OVN_VPN_PORTS=1194 OVN_PROTO=udp OVN_TLS=selfsigned \
OVN_TLS_CERT="$WORK/tls/fullchain.pem" OVN_KEY=secretkey OVN_APP_DIR="$WORK/app" OVN_DATA_BASE="$WORK/data" \
  bash -c '. "'"$ROOT_DIR"'/lib.sh"; . "'"$ROOT_DIR"'/install.sh"; write_install_result "'"$WORK"'/data/install-result.env"' >/dev/null 2>&1
for key in OVNODE_ADDRESS OVNODE_PROTOCOL OVNODE_API_KEY OVNODE_CERT_FILE; do
    grep -q "^${key}=" "$WORK/data/install-result.env" || { echo "FAIL: missing $key"; exit 1; }
done
echo "ok: setup info persisted"
rm -rf "$WORK"

# ── cert SAN ───────────────────────────────────────────────────────────
echo "=== cert SAN ==="
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-cert-san-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tls" "$WORK/app"
printf 'SSL_KEYFILE=%s/tls/privkey.pem\nSSL_CERTFILE=%s/tls/fullchain.pem\n' "$WORK" "$WORK" > "$WORK/app/.env"
APP_DIR="$WORK/app" TLS_REGENERATE=1 bash -c '. "'"$ROOT_DIR"'/lib.sh"; generate_selfsigned' >/dev/null 2>&1
openssl x509 -in "$WORK/tls/fullchain.pem" -noout -text | grep -q "IP Address:" || { echo "FAIL: no IP SAN"; exit 1; }
echo "ok: self-signed cert includes IP SAN"
rm -rf "$WORK"

# ── compose syntax ─────────────────────────────────────────────────────
echo "=== compose ==="
bash -n "$ROOT_DIR/scripts/compose/entrypoint.sh" || { echo "FAIL: entrypoint"; exit 1; }
echo "ok: entrypoint passes bash -n"
if command -v docker >/dev/null 2>&1; then
    tmpenv="$ROOT_DIR/.env"; touch "$tmpenv"
    docker compose -f "$ROOT_DIR/scripts/compose/docker-compose.yml" config >/dev/null
    rm -f "$tmpenv"
    echo "ok: compose config valid"
else
    echo "skip: docker not installed"
fi

# ── credentials output ─────────────────────────────────────────────────
echo "=== credentials ==="
if [[ $EUID -ne 0 ]]; then
    echo "skip: must run as root"
else
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-credentials-test.XXXXXX")"
    trap 'rm -rf "$WORK"' EXIT
    mkdir -p "$WORK/tls"
    openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls/privkey.pem" \
        -out "$WORK/tls/fullchain.pem" -days 1 -nodes -subj "/CN=test" >/dev/null 2>&1
    printf 'NODE_NAME=testnode\nSERVICE_PORT=2083\nTLS_METHOD=selfsigned\nSSL_CERTFILE=%s/tls/fullchain.pem\nAPI_KEY=secretkey\n' "$WORK" > "$WORK/.env"
    OVN_APP_DIR="$WORK" "$ROOT_DIR/ovnode.sh" auth key >"$WORK/out.txt" 2>&1
    grep -qF "API key        secretkey" "$WORK/out.txt" || { echo "FAIL: API key missing"; cat "$WORK/out.txt"; exit 1; }
    grep -q "BEGIN CERTIFICATE" "$WORK/out.txt" || { echo "FAIL: cert missing"; cat "$WORK/out.txt"; exit 1; }
    echo "ok: credentials prints API key and certificate"
    rm -rf "$WORK"
fi
