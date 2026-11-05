# Roadmap

Lightweight filter applies. Stdlib only, no new deps, smallest diff wins.

## Shipped (v2.0.1 — hardening release)

- API-key hashing (keys shorter than 16 chars refused, HTTP 503).
- Rate limit: per-IP before auth, global after auth (429, 10 failed keys in 5 min).
- First boot prints a key fingerprint instead of the full API key.
- Pushed PEMs are parsed, validated and re-encoded.
- PKI push takes a lock and rolls back partial writes.
- Revoking a user revokes every valid certificate of that name.
- CRL refreshed daily; /sync/status reports crl_days_remaining.
- Secret permissions repaired on start/restart; symlinks never followed.
- Installer verifies a minisign signature (OVN_ALLOW_UNSIGNED=1 to skip).
- POST /sync/config validates before writing, refuses reserved ports.
- CN rules: no leading dot, must equal its sanitized form.
- .env is not read from the current directory.

## Shipped — retired 1.1.x items

- 1.1.0 UX overhaul, 1.1.1 username lock, 1.1.2 `.env` layering, `/api/login`
  rate limit, typed `ovmanager update` confirmation — superseded by the 2.0.x
  line. See the CHANGELOG.

## Deferred (over-engineered for lightweight)

- TOTP 2FA (new dep, recovery flow, QR UI)
- Encrypted backup/restore (only ship if it's `tar czf` + DB re-seed, no crypto
  layer)
- Bulk user actions
- Stale-node auto-hide (cosmetic)