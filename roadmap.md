# Roadmap

Lightweight filter applies. Stdlib only, no new deps, smallest diff wins.

## Shipped

- **1.1.1** — owner username lock + last-user guard.
- **1.1.0** — full UX overhaul (dashboard, list pages, settings, shell).

## Shipped (v1.1.2)

- Rate-limit `/api/login` — already implemented in OVManager auth (token bucket).
- `ovmanager update` typed confirmation — implemented in Go CLI (`--yes` to skip).
- Last-login IP + timestamp — surfaced in user detail modal.

## Later (v1.1.3)


## Deferred (over-engineered for lightweight)

- TOTP 2FA (new dep, recovery flow, QR UI)
- Encrypted backup/restore (only ship if it's `tar czf` + DB re-seed,
  no crypto layer)
- Bulk user actions
- Stale-node auto-hide (cosmetic)