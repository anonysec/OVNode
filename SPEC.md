# OVNode contract spec (condense baseline)

One-page contract for the node agent. Phase 2 may delete anything not listed
here; nothing listed here may change behavior.

## Features that survive
- `/sync/*` HTTP API: health, status, usage, sessions, logs, config, restart,
  renew-cert, update, user create/status/limit/delete/disconnect/reset-usage,
  download/ovpn, users bulk-limits, push creds/pki. Auth: `key` header + panel
  pairing lease (X-Panel-ID), TLS pinned CA.
- `ovnode` CLI: status config info update enable disable restart restart-vpn
  logs backup restore auto-backup tls rollback recover-update uninstall
  completion help start stop; `ovnode rollback` refuses on v2 counters.
- Hooks: connect/disconnect via the same binary; generation-safe accounting.
- PKI: CA init, client/server issuance, revocation (CRL), partial-identity
  preservation, exact owned-hook repair.
- NAT: `VPN_NAT_ENABLED` enrollment, owned rules only (`ovnode-nat` /
  `ovnode-redirect` comments), primary+extra port sync via `nat apply`.
- Installer: install/update/uninstall, pre-update state snapshot + verified
  restore, release binary verified against the release SHA256SUMS before
  install, native systemd units.

## Frozen contracts
- Usage counter v2 JSON (`version, epoch, total, sessions`, filename
  `marker_key`); legacy unsigned digits accepted once as starting total;
  malformed/empty/unknown version = unavailable, never zeroed.
- `totals`/`totals_epochs` same contributor set; epoch format
  `<nanos>-<counter>`.
- Profile/resume/cache file formats; `.env` keys (never edited by code paths
  except installer-owned writes).
- Exit codes and CLI output shape (fd 2, colour rules).

## Invariants (each has a test)
- Count once: poll/bank/reset/retention keyed by generation identity,
  session→usage lock order, receipts pruned only after marker absence.
- Fail-closed codes: no rollback onto v2 state; no status-only fallback
  identity; malformed v2 never replaced.
- Security: symlink-safe locks, no-follow descriptors, runtime-group perms,
  managed-password access, dropped-UID hook operation.
- Lifecycle: create → policy → download serial; delete → signed CRL before
  cleanup; disabled tombstone retention.

## Explicitly out
- Node-room for several nodes per host (single-node layout only).
- Second NAT script (`ovnode-nat.sh` removed; native binary only).
- Browser/web UI tied to addon features not changing node behavior.
- Deprecated hook names / legacy counter read-limits beyond the v0 entry.
