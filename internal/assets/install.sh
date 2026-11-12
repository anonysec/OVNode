#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2012,SC2015,SC2016,SC1091
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
# Bootstrap: fetch, verify, then exec the Go installer.
set -Eeuo pipefail
VERSION="${Version:-latest}"
REPO="${Repo:-anonysec/OVNode}"
AppDir="${AppDir:-/opt/ovnode}"
BIN_DIR="${BinDir:-/usr/local/bin}"
fail() { printf '\n  Error: %s\n\n' "$1" >&2; exit "${2:-1}"; }
# only scan for pin/local flags; Go parses everything else
PIN="${Version:-}"; LOCAL=0; SRC_DIR="${SrcDir:-$PWD}"
prev=""
for arg in "$@"; do
  case "$prev" in
    --version|-v) PIN="$arg" ;;
    --src) SRC_DIR="$arg" ;;
  esac
  [[ "$arg" == "--local" ]] && LOCAL=1
  prev="$arg"
done
if [[ -n "$PIN" ]]; then
  [[ "$PIN" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] || fail "Bad --version '$PIN' (use 1.2.3, v1.2.3, 1.2.3-rc1)" 2
  VERSION="${PIN#v}"
fi
if [[ "$LOCAL" -eq 1 ]]; then
  command -v go >/dev/null 2>&1 || fail "go is required for --local builds"
  mkdir -p "$AppDir"
  ( cd "$SRC_DIR" && go build -o "$AppDir/ovnode" ./cmd/ovnode ) || fail "local build failed"
  BIN="$AppDir/ovnode-server"
  [[ -x "$BIN" ]] || BIN="$AppDir/ovnode"
  "$BIN" assets write --dest "$AppDir" >/dev/null || true
  exec "$BIN" install "$@"
fi
if [[ "$VERSION" == "latest" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$VERSION" ]] || fail "Could not resolve latest release for $REPO"
fi
case "$VERSION" in
  dev|dev-*) TAG="dev" ;;
  *) TAG="v$VERSION" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) fail "Unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
esac
ASSET="ovnode-linux-$ARCH"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"
SUMS_URL="https://github.com/$REPO/releases/download/$TAG/SHA256SUMS"
command -v curl >/dev/null 2>&1 || fail "curl is required to download the release"
mkdir -p "$AppDir"
# Always fetch and verify the requested release. Reusing a leftover
# $AppDir/ovnode was how an older installer kept running after an install or
# a failed attempt; the release tag, not a stale file, is the target.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -fsSL --max-time 60 --retry 3 --retry-delay 2 --retry-max-time 120 -o "$TMP/$ASSET" "$URL" || fail "No release file for v$VERSION, see https://github.com/$REPO/releases"
curl -fsSL --max-time 60 --retry 3 --retry-delay 2 --retry-max-time 120 -o "$TMP/SHA256SUMS" "$SUMS_URL" || fail "Could not download SHA256SUMS for v$VERSION, refusing to install an unverified release"
( cd "$TMP" && grep " $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null ) || fail "Checksum verification failed for $ASSET (v$VERSION): SHA256SUMS is missing a line for $ASSET or the download does not match, refusing to install"
install -m 0755 "$TMP/$ASSET" "$AppDir/ovnode"
rm -rf "$TMP"; trap - EXIT
printf '  ok    release v%s verified and installed\n' "$VERSION" >&2
# Run the binary downloaded in this run: it carries this run's installer
# fixes and is the only copy whose checksum was just verified.
BIN="$AppDir/ovnode"
"$BIN" assets write --dest "$AppDir" >/dev/null || true
exec "$BIN" install "$@"
