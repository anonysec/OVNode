# Roadmap

Lightweight filter applies. Stdlib only, no new deps, smallest diff wins.

## Shipped

- **1.1.1** — owner username lock + last-user guard.
- **1.1.0** — full UX overhaul (dashboard, list pages, settings, shell).

## Next (v1.1.2)

Smallest set. Each item is ≤ 1 day, no new dependencies.

1. **Rate-limit `/api/login`** — in-process token bucket keyed on IP + username,
   ~30 lines, no middleware.
2. **`ovm update` typed confirmation** — `read -p` + case match in `manager.sh`.
   Stops the silent self-upgrade foot-gun.
3. **Last-login IP + timestamp on header** — almost certainly already in
   `sessions` / `audit_log`, just surface.

## Later (v1.1.3)

4. **`ovm doctor` round-trip** — login + node API ping via `curl`. Catches
   JWT-secret drift and node TLS expiry that current checks miss.
5. **Audit log → CSV export** — stdlib `csv` + one button in `AuditLog.tsx`.

## Deferred (over-engineered for lightweight)

- TOTP 2FA (new dep, recovery flow, QR UI)
- Encrypted backup/restore (only ship if it's `tar czf` + DB re-seed,
  no crypto layer)
- Bulk user actions
- Stale-node auto-hide (cosmetic)