# Changelog

## 2.0.2 — 2026-09-07

Pairs with OVManager panel `2.x`.

- Reconnect: dynamic-IP `max_logins=1` takeovers verified via mgmt-live
  check, kill all CIDs for the CN, status-aware grace, per-(CN,pool) dead
  cleanup; keepalive 10 60 fresh-only.
- Restart policy: no-op push = zero daemon restarts, tunnel-only = no
  signal, proto/port = one restart, normalization = SIGHUP; entrypoint
  watches content hash + dual-proto NAT with stale prune.
- Hook perf: one python mgmt session per takeover, builtin marker parsing,
  single status prefilter, EPOCHSECONDS, per-CN locks.
- Low-end: users/<cn>/{limit,disabled} merged into one 0644 `state` file
  (dual-read fallback, writer converges, `.lock` cleanup); status
  mtime+size parse cache shared by all endpoints; fresh verb 2, P-256.
- Obs: hook ip/pool on decisions, client IP on 401/429; usage-reset
  endpoint; `ca_expiry`/`server_expiry` in status.
- Fresh defaults: no legacy ciphers, mssfix/buffers, no-compression,
  block-outside-dns, TLS 1.3, ipp flush, max-clients 250, fast-io on UDP.
- Installer: `--proto`/`OVN_PROTO` prompt, docker liveness check,
  native-HUP logrotate, evict native openvpn daemon on docker
  install/update, env recovery survives missing `.env` keys.

## 2.0.1 — 2026-09-05

- P1 batch: single `server.conf` writer, easyrsa lock, usage-reset
  endpoint, `ca_expiry`/`server_expiry` in status, firewall cleanup.
- Installer test hermetic on installed machines (`OVN_APP_DIR`).
- Docs: badges, compat matrix, `OVN_REPO` fork override.

## 2.0.0 — 2026-09-05

Pairs with OVManager panel `2.x`.

- License: MIT (was proprietary).
- Fix: connect hook answers the management password challenge, so
  `max_logins=1` takeover kills work on hardened installs.
- Docker: supervisor restarts OpenVPN fully when `server.conf` changes
  (SIGHUP cannot rebind port/proto); NAT re-applied on restart.
- New: `GET /sync/config` reports live port/proto/tunnel (drift detect).
- Perf: API-TLS cert expiry cached 5 min (was an `openssl` fork per poll).
- Lint gate clean (`ruff format --check`).
- Headers: SPDX-MIT across the tree.

## 1.6.0

- Pre-freeze state: ECDSA PKI, dynamic-IP-safe sessions, multi-port,
  per-user store, envelope sync API.
