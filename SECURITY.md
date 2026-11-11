# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.0.x   | yes       |
| 1.x     | no        |
| < 1.0   | no        |

Upgrade together with the panel: node `2.0.x` (current line) pairs with OVManager `2.x`.

## Reporting a vulnerability

**Do not open a public issue.** Use
[GitHub Private Vulnerability Reporting](../../security/advisories/new)
or email the maintainer address listed on the repository profile.

Include: affected version(s), steps to reproduce, impact. Acknowledgement
within 7 days, fix timeline within 30 days, 90-day disclosure after fix.

## Threat model notes

- The API key is the full node control secret: any holder can push PKI,
  restart or trigger a self-update. Treat it like a root credential and
  rotate it with `ovnode auth rotate` on suspected exposure.
- A single panel holds the node lease; a second panel is refused with 409.
- The self-updater only runs a root-owned, non-writable `install.sh`.

## Threat model

The API key grants full control of the node (users, restart, update, PKI push). The key must travel only over TLS and be rotated by reinstall. A node trusts one panel at a time (30-minute lease).

## Scope

In scope: sync-API authentication (`key` header), management-interface
password handling, PKI file permissions, installer privilege handling.

Out of scope: DDoS, OpenVPN/EasyRSA upstream CVEs, social engineering.

## Hardening checklist (production)

- `ApiKey` ≥ 32 hex chars, unique per node; `use_tls=true` in the panel.
- Keep the installer-managed file permissions (`mgmt-pass` 0600,
  OpenVPN runtime user `nobody`); do not run the agent as root services
  beyond what the installer sets up.
- Back up the OpenVPN root (`/var/lib/<instance>/openvpn`) before every update and test restores.
