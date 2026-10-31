#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# Docker parity check: entrypoint syntax and compose configuration.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$HERE")"

bash -n "$ROOT_DIR/scripts/compose/entrypoint.sh"
echo "ok: entrypoint passes bash -n"

if ! command -v docker >/dev/null 2>&1; then
    echo "skip: docker not installed"
    exit 0
fi

tmpenv="$ROOT_DIR/.env"
trap 'rm -f "$tmpenv"' EXIT
touch "$tmpenv"
docker compose -f "$ROOT_DIR/scripts/compose/docker-compose.yml" config >/dev/null
echo "ok: compose configuration is valid"
