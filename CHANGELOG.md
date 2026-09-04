# Changelog

## 2.0.0 (unreleased) — freeze + harden

Pairs with OVManager panel `2.x`.

- License: MIT (was proprietary).
- Fix: connect hook answers the management password challenge, so
  `max_logins=1` takeover kills work on hardened installs.
- Docker: supervisor restarts OpenVPN fully when `server.conf` changes
  (SIGHUP cannot rebind port/proto); NAT re-applied on restart.
- New: `GET /sync/config` reports live port/proto/tunnel (drift detect).
- Perf: API-TLS cert expiry cached 5 min (was an `openssl` fork per poll).
- Headers: SPDX-MIT across the tree.

## 1.6.0

- Pre-freeze state: ECDSA PKI, dynamic-IP-safe sessions, multi-port,
  per-user store, envelope sync API.
