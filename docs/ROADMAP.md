# OVNode roadmap

> Status: all steps shipped in **2.1.0** (2026-09-17), alongside OVManager 2.1.0.

OVNode is the VPN-node half of the plan tracked in
[OVManager's roadmap](https://github.com/anonysec/OVManager/blob/main/docs/ROADMAP.md).
This file lists the node-specific work.

## Step 1 — Reliability/security fixes

- `client.ovpn` files (they contain the client's private key) are created
  with owner-only permissions from the start, written atomically, and removed
  if generation fails.
- A retried delete regenerates the certificate revocation list so a revoked
  client can never stay connected.
- API key checks: rate limiting keyed by client IP (not the attacker-supplied
  key), constant-time compare safe for non-ASCII input, heavy limit on the
  lazy certificate path.
- Login limits are only changed when the panel actually sends `max_logins`.
- The OpenVPN initialization critical section is locked; `server.conf` keeps a
  reloadable mode after privilege drop.
- Installer: private backups, `mktemp` downloads, no plain HTTP.

## Step 2 — Installer and terminal menu

- Start menu: `Express / Custom / Update / Uninstall`; TLS = self-signed
  (default) / Let's Encrypt (domain or IP) / custom paths.
- `ovnode` / `ovn` terminal menu: status, agent/VPN service control, logs,
  backup, update, TLS, uninstall.

## Step 3–5 — Node features for the redesign

- Advanced settings from the panel (DNS, IPv6, extra ports) with Apply and
  rollback; OpenVPN/agent version reporting and update endpoint.
- Certificate expiry visibility and one-click renew.
