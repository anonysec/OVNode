# How OVNode works

A plain-language tour of the node side — no programming knowledge needed.
Read it together with [OVManager's page](https://github.com/anonysec/OVManager/blob/main/docs/how-it-works.md):
the panel is the control room, the node is the VPN server.

## The big picture

OVNode is the agent that runs on every VPN server. It does two jobs:

* **Serves the panel's API** — user creation, limits, configs, traffic
  numbers, diagnostics.
* **Owns OpenVPN** — server configuration, certificates, and the connect /
  disconnect hooks that count traffic and enforce limits.

It implements exactly the sync API OVManager expects. **The node never calls
the panel**; all traffic goes panel → node, so a node does not even store the
panel's address.

## What runs where

* **The agent:** a small web API process, listening on the service port
  (`2083` by default).
* **OpenVPN:** the VPN daemon, managed by the agent via the installer/systemd
  natively, or supervised by the container entrypoint in Docker.
* **The hooks:** tiny scripts installed into OpenVPN's `ovnode/scripts/` that
  run at connect and disconnect time — where limits and traffic counting
  actually happen.

There is no database. Everything is plain files on disk.

## How the panel talks to the node

Every request from the panel carries the shared **API key** in a `key`
header, and every response is the same envelope:

```text
{"success": true, "msg": "...", "data": {...}}
```

The endpoints map one-to-one to things the panel needs: status, configure
OpenVPN, create/update/delete a user, set a login limit, disconnect, download
a `.ovpn`, and report usage and sessions. With TLS on (recommended) the API
key is encrypted in transit; with TLS off it travels in clear text. Self-signed
certificates are the default; switch to Let's Encrypt when you have a domain.

## Identity and the per-user folder

The panel's numeric user id *is* the OpenVPN common name (CN) — user 42 gets
certificate CN `42`. The node keeps the display username in a `name` file next
to it so usage can be reported by name. One folder per user:

```text
/etc/openvpn/ovnode/users/<cn>/
├── name         panel username
├── state        login limit + disabled flag (read by the hooks)
└── client.ovpn  cached profile, regenerated on demand
```

Deleting or disabling a user revokes the certificate (CRL) and removes the
folder. Older "legacy" layouts are migrated automatically on agent start, so
restoring an old backup just works.

## Traffic accounting

OpenVPN's hooks write a small marker file when a user connects and, on
disconnect, bank the session's final byte counters. `/sync/usage` combines
both: **lifetime totals** per user = banked bytes from completed sessions plus
bytes flowing in live sessions. The panel polls this and does the billing
(see the OVManager page); the node also reports raw per-session numbers.

## Limits and sessions

`max_logins` is enforced **locally at connect time** by the hooks: 1 means a
new connection takes over the old one, N rejects the N+1th, and 0 is
unlimited. Session identity is the CN plus the VPN pool IP, which stays stable
for the life of a session — so mobile and CGNAT users whose real IP changes on
every reconnect are still counted and limited. Cross-node policy lives in the
panel, which aggregates sessions and can disconnect a user anywhere.

## Security model

* API key in the `key` header on every request; optional TLS.
* The OpenVPN management interface listens on localhost only and requires a
  password file, because host networking and containers can share localhost.
* Modern PKI: ECDSA certificates, `tls-crypt`, TLS 1.2+, CRL enforcement, and
  OpenVPN drops privileges to an unprivileged runtime user.
* PKI failures start the agent in diagnostics mode instead of killing it.

## Updates

`ovnode update` (or **Update** in the `ovnode`/`ovn` terminal menu) pulls the
latest code, backs up data and PKI first, and restarts. The same menu has
start/stop/restart, restart-VPN, logs and backup — all scriptable commands.

## Backup and restore

`ovnode backup` saves the agent's state (`ovnode/`) and the PKI as two tar
archives in `/var/backups` (newest 14 kept; `--keep N` changes that, and
`ovnode auto-backup on` adds a daily systemd timer). Restore is copying those
two paths back; the agent
migrates an older layout on start. Uninstall keeps data unless `--purge`.
