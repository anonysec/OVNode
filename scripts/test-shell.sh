#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Duplicate function check: shared shell functions exist exactly once.
echo "=== duplicate function check ==="
# Extract function names from lib.sh
lib_funcs=$(grep -oE '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' internal/assets/lib.sh | tr -d '()' | sort -u)
dupes=""
for f in internal/assets/install.sh internal/assets/ovnode.sh; do
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
for f in internal/assets/install.sh internal/assets/ovnode.sh internal/assets/lib.sh; do
    bash -n "$f" || { echo "FAIL: $f"; exit 1; }
done
echo "OK: all shell files pass bash -n"

# Version parity
echo "=== version parity ==="
v_install=$(Version="$(go run "${ROOT_DIR}/cmd/ovnode" version 2>/dev/null || echo "")" bash -c '. "'"${ROOT_DIR}"'/internal/assets/install.sh"; echo "$VERSION"' 2>/dev/null || grep -m1 '^VERSION=' "${ROOT_DIR}/internal/assets/ovnode.sh" | cut -d= -f2 | tr -d '"')
v_ovnode=$(grep -m1 '^VERSION=' "${ROOT_DIR}/internal/assets/ovnode.sh" | cut -d= -f2 | tr -d '"')
v_binary=$(go run "${ROOT_DIR}/cmd/ovnode" version 2>/dev/null || echo "unknown")
echo "install.sh: $v_install"
echo "ovnode.sh:  $v_ovnode"
echo "binary:     $v_binary"
if [ "$v_install" != "$v_ovnode" ] || [ "$v_install" != "$v_binary" ]; then
    echo "FAIL: version mismatch"
    exit 1
fi
echo "OK: versions match"

# ── cert SAN ───────────────────────────────────────────────────────────
echo "=== cert SAN ==="
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-cert-san-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tls" "$WORK/app"
printf 'TlsKeyFile=%s/tls/privkey.pem\nTlsCertFile=%s/tls/fullchain.pem\n' "$WORK" "$WORK" > "$WORK/app/.env"
AppDir="$WORK/app" TLS_REGENERATE=1 bash -c '. "'"$ROOT_DIR"'/internal/assets/lib.sh"; generate_selfsigned' >/dev/null 2>&1
openssl x509 -in "$WORK/tls/fullchain.pem" -noout -text | grep -q "IP Address:" || { echo "FAIL: no IP SAN"; exit 1; }
echo "ok: self-signed cert includes IP SAN"
rm -rf "$WORK"

# ── incompatible usage counters block code-only rollback ────────────────
echo "=== usage counter rollback gate ==="
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-usage-gate-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/app" "$WORK/data/usage"
printf 'DataDir=%s/data\n' "$WORK" > "$WORK/app/.env"
gate_check() {
    AppDir="$WORK/app" DATA_BASE="$WORK/data" bash -c '. "'"$ROOT_DIR"'/internal/assets/lib.sh"; has_incompatible_usage_counters'
}
printf '12345\n' > "$WORK/data/usage/alice"
gate_check && { echo "FAIL: legacy digits flagged incompatible"; exit 1; }
printf '999\n' > "$WORK/data/usage/bob"
gate_check && { echo "FAIL: legacy digits flagged incompatible"; exit 1; }
printf '{"version":2,"epoch":"e1","total":5,"sessions":{}}\n' > "$WORK/data/usage/alice"
gate_check || { echo "FAIL: v2 counter not flagged incompatible"; exit 1; }
rm "$WORK/data/usage/alice"
: > "$WORK/data/usage/alice"
gate_check || { echo "FAIL: empty counter not flagged incompatible"; exit 1; }
printf 'corrupt\n' > "$WORK/data/usage/alice"
gate_check || { echo "FAIL: corrupt counter not flagged incompatible"; exit 1; }
rm -rf "$WORK/data/usage"
gate_check && { echo "FAIL: missing usage dir flagged incompatible"; exit 1; }
grep -q 'has_incompatible_usage_counters' "$ROOT_DIR/internal/assets/ovnode.sh" \
    || { echo "FAIL: do_rollback does not enforce the gate"; exit 1; }
echo "ok: v2/corrupt counters block code-only rollback, legacy digits allowed"
rm -rf "$WORK"

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
    printf 'Instance=testnode\nApiPort=2083\nTlsCertFile=%s/tls/fullchain.pem\nApiKey=secretkey\n' "$WORK" > "$WORK/.env"
    AppDir="$WORK" "$ROOT_DIR/internal/assets/ovnode.sh" auth key >"$WORK/out.txt" 2>&1
    grep -qF "API key        secretkey" "$WORK/out.txt" || { echo "FAIL: API key missing"; cat "$WORK/out.txt"; exit 1; }
    grep -q "BEGIN CERTIFICATE" "$WORK/out.txt" || { echo "FAIL: cert missing"; cat "$WORK/out.txt"; exit 1; }
    echo "ok: credentials prints API key and certificate"
    rm -rf "$WORK"
fi
