# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.x     | yes       |
| < 2.0   | no        |

Upgrade together with the panel: node `2.x` pairs with OVManager `2.x`.

## Reporting a vulnerability

**Do not open a public issue.** Use
[GitHub Private Vulnerability Reporting](../../security/advisories/new)
or email the maintainer address listed on the repository profile.

Include: affected version(s), steps to reproduce, impact. Acknowledgement
within 7 days, fix timeline within 30 days, 90-day disclosure after fix.

## Scope

In scope: sync-API authentication (`key` header), management-interface
password handling, PKI file permissions, installer privilege handling.

Out of scope: DDoS, OpenVPN/EasyRSA upstream CVEs, social engineering.

## Hardening checklist (production)

- `API_KEY` ≥ 32 hex chars, unique per node; `use_tls=true` in the panel.
- Keep the installer-managed file permissions (`mgmt-pass` 0600,
  OpenVPN runtime user `nobody`); do not run the agent as root services
  beyond what the installer sets up.
- Back up `/etc/openvpn` (PKI + store) before every update and test restores.
