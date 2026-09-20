# Changelog

## 1.1.1 — 2026-09-19

Concept-A split: the installer (`install.sh`) only installs, updates and
uninstalls; day-to-day operations move to the manager (`manager.sh`,
installed as `ovnode`/`ovn`) with a numbered menu. Shared shell code lives
in `lib/common.sh`. Updating auto-swaps the old installer-copy CLI for the
manager. `--tls` takes numbers 1-4 (names still accepted); `status`/`logs`/
`backup`/`tls` on `install.sh` now redirect to `ovn`. Also fixed: the TLS
menu called an undefined `kv`, and `spinner` could end with a failing test
under `set -e`.

## 1.1.0 — 2026-09-19

Version reset: the `2.x` release line is retired and the project continues
on the `1.x` line. No code changes in this release — version strings only.
Pairs with OVManager panel `1.2.2` (same sync API contract).

- `pyproject.toml`, `core/version.py`, `install.sh` and the README badge now
  report `1.1.0`.
- All `2.x` GitHub releases, tags and container images are removed.

## 1.6.0

- Pre-freeze state: ECDSA PKI, dynamic-IP-safe sessions, multi-port,
  per-user store, envelope sync API.
