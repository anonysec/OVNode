#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# Regression test: `ovnode credentials` must print both the API key and the
# node certificate, so an operator can copy both into the panel from one
# command.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$HERE")"
OVNODE_SH="$ROOT_DIR/ovnode.sh"
LIB_SH="$ROOT_DIR/lib.sh"

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-credentials-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/tls"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls/privkey.pem" \
    -out "$WORK/tls/fullchain.pem" -days 1 -nodes -subj "/CN=test" >/dev/null 2>&1
printf 'NODE_NAME=testnode\nSERVICE_PORT=2083\nTLS_METHOD=selfsigned\nSSL_CERTFILE=%s/tls/fullchain.pem\nAPI_KEY=secretkey\n' "$WORK" > "$WORK/.env"

OVN_APP_DIR="$WORK" "$OVNODE_SH" auth key >"$WORK/out.txt" 2>&1

grep -qF "API key        secretkey" "$WORK/out.txt" || { echo "API key missing"; cat "$WORK/out.txt"; exit 1; }
grep -q "BEGIN CERTIFICATE" "$WORK/out.txt" || { echo "certificate missing"; cat "$WORK/out.txt"; exit 1; }
echo "ok: credentials prints API key and certificate"