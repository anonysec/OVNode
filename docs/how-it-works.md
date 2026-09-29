# How OVNode works

A plain-language tour of the node side — no programming knowledge needed. Read
it together with
[OVManager's page](https://github.com/anonysec/OVManager/blob/main/docs/how-it-works.md):
the panel is the control room, the node is the VPN server.

## The big picture

OVNode is the agent that runs on every VPN server. It has two jobs:

* **Serve the panel's API** — user creation, limits, configs, traffic numbers,
  diagnostics.
* **Own OpenVPN** — server configuration, certificates, and the connect and
  disconnect hooks that count traffic and enforce limits.

It implements exactly the sync API OVManager expects. **The node never calls the
panel**; all traffic goes panel → node, so a node does not even store the panel's
address. Move or replace the panel and the nodes keep working — re-add them with
the same address, name and API key.

## What runs where

* **The agent** — a small web API process listening on the service port
  (`2083` by default).
* **OpenVPN** — the VPN daemon, run by systemd on a host install, or supervised
  by the container entrypoint in Docker.
* **The hooks** — small scripts in OpenVPN's `ovnode/scripts/` that run at
  connect and disconnect time. That is where limits and traffic counting
  actually happen.

There is no database. Everything is plain files on disk.

## How the panel talks to the node

Every request carries the shared **API key** in a `key` header, and every
response has the same shape:

```text
{"success": true, "msg": "...", "data": {...}}
```

The panel treats a call as successful only when it gets HTTP 200 with
`"success": true`, so the node reports business failures inside the envelope
rather than as an HTTP error.

With TLS on (recommended) the API key is encrypted in transit; with TLS off it
travels in clear text. Self-signed is the default; Let's Encrypt is there for
when you have a domain.

The full endpoint list, and what each one maps to on the panel side, is the
table in [the README](../README.md#sync-api).

## Identity and the per-user folder

The panel's numeric user id *is* the OpenVPN common name (CN) — user 42 gets
certificate CN `42`. The node keeps the display username in a `name` file beside
it, so usage can be reported by name. One folder per user:

```text
/etc/openvpn/ovnode/users/<cn>/
├── name         panel username
├── state        login limit + disabled flag (read by the hooks)
└── client.ovpn  cached profile, regenerated on demand
```

Deleting a user revokes the certificate through the CRL and removes the folder.
Disabling only sets the marker and disconnects any live session — the
certificate and folder stay, so re-enabling is instant.

## Traffic accounting

The hooks write a marker file when a user connects and, on disconnect, bank the
session's final byte counters. `/sync/usage` combines both: **lifetime totals**
per user are the banked bytes from completed sessions plus the bytes flowing in
live sessions. The panel polls this and does the billing; the node also reports
the raw per-session numbers.

## Limits and sessions

`max_logins` is enforced **locally at connect time** by the hooks: `1` means a
new connection takes over the old one, `N` rejects the N+1th, and `0` is
unlimited. Session identity is the CN plus the VPN pool IP, which stays stable
for the life of a session — so mobile and CGNAT users whose real address changes
on every reconnect are still counted and limited. Cross-node policy lives in the
panel, which aggregates sessions and can disconnect a user anywhere.

## Security model

* API key in the `key` header on every request; optional TLS.
* The OpenVPN management interface listens on localhost only and requires a
  password file, because host networking and containers can share localhost.
* Modern PKI: ECDSA certificates, `tls-crypt`, TLS 1.3 minimum, CRL
  enforcement, and OpenVPN drops privileges to an unprivileged runtime user.
* Client profiles embed the private key, so they are created owner-only from the
  start and written atomically.
* PKI failures start the agent in diagnostics mode instead of killing it.

## Updates

`ovn update` (or **Update** in the `ovn` menu) takes a verified snapshot of the
identity file, the node data directory, `/etc/openvpn` and the API TLS files,
then swaps in the new release. If the new release does not come up healthy, the
snapshot is restored automatically. `ovn rollback` puts the previous code back;
`ovn recover-update` cleans up after an update that was interrupted.

`ovn` itself has start/stop/restart, restart-VPN, logs, backup, restore, TLS,
doctor and completion — all scriptable commands, not just a menu.

## Backup and restore

`ovn backup` archives `/var/lib/ovnode` (agent data) and the OpenVPN PKI
(`/etc/openvpn/server/pki`) into `/var/backups`, newest 14 kept — `--keep N`
changes that, and `ovn auto-backup on` adds a daily systemd timer.

`ovn restore` lists those archives and, given a name, unpacks one after taking a
safety copy of the current state first — it refuses to continue if that copy
cannot be made. The agent migrates an older on-disk layout on start, so
restoring a backup taken by an older build just works.

Uninstall keeps data unless you add `--purge`; its confirmation defaults to No.
