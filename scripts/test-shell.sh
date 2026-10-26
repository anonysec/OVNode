#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
set -euo pipefail

# Duplicate function check: shared shell functions exist exactly once.
echo "=== duplicate function check ==="
# Extract function names from lib.sh
lib_funcs=$(grep -oE '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' lib.sh | tr -d '()' | sort -u)
dupes=""
for f in install.sh ovnode.sh doctor.sh; do
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
for f in install.sh ovnode.sh lib.sh doctor.sh; do
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
