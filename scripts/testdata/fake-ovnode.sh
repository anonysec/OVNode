#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# The release binary, faked for the installer regression tests.
#
# install.sh fetches exactly one thing from the network — the release binary —
# and then asks it for everything else. Point REPO at a directory the tests
# publish and that fetch becomes a `file://` copy of this script, so the tests
# exercise the real bootstrap (fetch → `assets write` → `. lib.sh`) with no
# network and no real node.
#
# It must behave like the product on the one subcommand the bootstrap uses,
# and it must fail loudly anywhere else: a stub that silently succeeds at
# `ca init` would let do_install "pass" a step it never performed.
set -Eeuo pipefail

if [[ "${1:-}" == "assets" && "${2:-}" == "write" ]]; then
    dest=""
    shift 2
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dest) dest="${2:-}"; shift 2 ;;
            *)      printf 'fake ovnode: unknown option %s\n' "$1" >&2; exit 2 ;;
        esac
    done
    [[ -n "$dest" ]] || { printf 'fake ovnode: --dest is required\n' >&2; exit 2; }
    # The real binary writes the four shell files it embeds. The fake copies
    # them out of the checkout the tests were started from, which is the same
    # bytes the real one would embed.
    src="${FAKE_OVNODE_ASSETS:-}"
    [[ -n "$src" && -d "$src" ]] || {
        printf 'fake ovnode: FAKE_OVNODE_ASSETS is not a directory: %s\n' "${src:-<unset>}" >&2
        exit 1
    }
    mkdir -p "$dest"
    for f in install.sh ovnode.sh lib.sh doctor.sh; do
        cp -f "$src/$f" "$dest/$f"
    done
    chmod 0755 "$dest/install.sh" "$dest/ovnode.sh"
    chmod 0644 "$dest/lib.sh" "$dest/doctor.sh"
    printf 'fake ovnode: wrote the installer assets into %s\n' "$dest" >&2
    exit 0
fi

printf 'fake ovnode: refusing "%s" — this stub exists for the installer bootstrap only\n' "${*:-}" >&2
exit 1
