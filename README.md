# OVNode

The VPN server half of an [OVManager](https://github.com/anonysec/OVManager) deployment: one OpenVPN server, plus the small agent the panel drives it through.

<div align="center">
  <img src=".github/assets/banner.svg" alt="OVNode — the VPN server agent for OVManager" width="820">
  <br><br>

  [![Version](https://img.shields.io/badge/version-2.0.3-blue)](CHANGELOG.md)
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![CI](https://github.com/anonysec/OVNode/actions/workflows/ci.yml/badge.svg)](https://github.com/anonysec/OVNode/actions/workflows/ci.yml)
  [![Go](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)](go.mod)
  [![Runtime](https://img.shields.io/badge/runtime-systemd-555555)](#-install)
</div>


## Project Status

> **Stable release (v2.0.3)**
>
> This repository is a stable, production-ready release. The API, configuration format and deployment model are frozen for this line; the changelog lists every change. Use it on VPN servers.

## 📖 Table of contents

- [What is this?](#-what-is-this)
- [Why this one?](#-why-this-one)
- [Features](#-features)
- [Install](#-install)
- [After it finishes](#-after-it-finishes)
- [Sync API](#-sync-api)
- [Day-to-day commands](#-day-to-day-commands)

- [Docs](#-docs)
- [License](#-license)

## 🧭 What is this?

> OVNode turns one Linux server into a VPN server, and gives the panel a way to run it.
>
> It sets up OpenVPN, generates and signs the certificates, writes the client profiles, counts each session's traffic and enforces each user's login limit.
>
> Install it on every machine that should carry VPN traffic, then register that machine in OVManager once. After that the panel is in charge — and the node never calls the panel, so the panel can be moved or replaced without touching any node.

## 💡 Why this one?

- **The panel holds the secrets, the node holds the traffic.** A node does not store the panel's address and never initiates a connection, so replacing the panel is a panel-side operation. Re-attach the nodes with the same name, address and key.
- **Limits enforced where the connections are.** The login limit runs in OpenVPN's connect hook, not in the panel, so it holds even while the panel is unreachable.
- **Traffic that survives reconnects.** The disconnect hook banks each session's final byte counters into a lifetime total per user, so a dropped connection or a restart cannot lose the count.
- **Nothing to migrate.** There is no database. Node state is plain files under `/var/lib/ovnode`, which is what makes `ovnode backup` a tarball and a restore a file copy.
- **Upgrades that keep your edits.** Hardening directives are appended to an existing `server.conf` rather than replacing it, and an older on-disk layout is migrated when the agent starts, so restoring an old backup just works.
- **A verified identity at all times.** Every panel request carries the node's API key, and the panel is the side that dials — so a node is reachable only by something that already knows the key.

## ✨ Features

### 🔐 OpenVPN, wired end to end
- The agent generates the PKI and `server.conf` on first boot.
- The installer adds IP forwarding, NAT masquerade, port redirects, `ufw`/`firewalld` openings, log rotation and a systemd unit (or a compose file).
- Hardened defaults: ECDSA `prime256v1` PKI, `tls-crypt`, `remote-cert-tls client`, `tls-version-min 1.3` in the generated configuration, AES-GCM, compression off, and CRL enforcement.
- TLS versions: the VPN data and control channel requires TLS 1.3 (`tls-version-min 1.3`); the panel API on port 2083 accepts TLS 1.2 or newer.
- OpenVPN drops privileges to an unprivileged runtime user, and the management interface listens on localhost only behind a password file.
- PKI failures start the agent in diagnostics mode instead of killing it, so you can still reach it to see what went wrong.

### 👤 Users and profiles
- The panel's numeric user id *is* the OpenVPN common name: user `42` gets certificate CN `42`. The display name is kept beside it, so usage can be reported by name.
- One folder per user under `/var/lib/ovnode/openvpn/users/<cn>/`, holding the name, the state (login limit and disabled flag) and a cached profile.
- Generated `.ovpn` files embed the private key and the `tls-crypt` key inline, are written owner-only and are created atomically.
- Disabling a user sets a marker and disconnects any live session; the certificate and folder stay, so re-enabling is instant. Deleting revokes the certificate through the CRL and removes the folder.
- Profiles are created lazily on first download, so a user who never connects costs nothing.

### 📊 Traffic and limits
- `max_logins` is enforced locally at connect time: `1` takes over the old session, `N` rejects the N+1th, `0` is unlimited.
- Session identity is the CN plus the VPN pool address, which stays stable for the life of a session — so users whose real address changes on every reconnect are still counted and limited correctly.
- `/sync/usage` reports a lifetime total per user: bytes banked from completed sessions plus bytes still flowing in live sessions.
- Per-session numbers and stale session markers are reported too, so the panel can rebuild its view after a restart.

### 🌐 Networking
- Multi-port: one OpenVPN instance reachable on several ports, with every profile listing all of them as `remote` lines so clients fail over when an ISP blocks one.
- Optional IPv6: a ULA pool and an IPv6 route push.
- Panel-managed DNS: the resolvers the panel pushes win over installer defaults, and survive a configuration regeneration.
- `OVN_NO_NAT=1` skips forwarding, NAT and port redirects when you would rather handle them yourself.

### 🔧 Operations
- `ovnode update` takes a verified snapshot of the identity file, the node data directory, the OpenVPN root and the API TLS files, then swaps in the release and restores the snapshot if the new one does not come up healthy.
- `ovnode rollback` returns to the previous code tree; it refuses to run while any v2 usage counter is present (the previous binary cannot read them) and points at a state restore instead; `ovnode update` cleans up an update interrupted by a reboot or power loss before it starts a new one.
- **Usage counter format (v2) and downgrade.** The per-CN usage file is a version-2 JSON counter (`version`, `epoch`, `total`, `sessions`) that commits total, session offsets and completed receipts atomically. A legacy unsigned-integer file is accepted once as the starting total. Empty, corrupt, or unknown-version files are reported as unavailable, never zeroed. Binaries that predate the v2 counter cannot decode these files and must not be run against them: a code-only downgrade against live v2 state would treat the JSON as an unreadable digit file and overwrite history. To downgrade, quiesce traffic (stop the agent and OpenVPN so no hook or poll can write), then restore the verified matching pre-update state snapshot taken by `ovnode update`; do not carry v2 usage files back to the older binary. Restoring an older snapshot discards any accounting recorded after that snapshot (a post-snapshot gap: those bytes are not recovered, and the panel's held baselines/epochs treat the rollback as an unexplained decrease until a reset reseeds).
- `ovnode backup` archives the node data and PKI into root-only tarballs, on demand or through a daily system timer, with retention you set.
- Log rotation, disk-space checks and a stable set of exit codes, so `ovnode` is scriptable rather than menu-only.

## 🚀 Install

**Before you start:**

- A Linux server — Debian or Ubuntu recommended. The panel's own server is fine; one node and one panel can share a host.
- Root, or an account with `sudo`.
- A host with systemd for the install.
- `1194/udp` reachable by your users, and `2083/tcp` reachable from the panel.

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh) -y

# Pin the installer to a release tag instead of `main`; the release
# `SHA256SUMS` file lists the SHA-256 of each release binary.
```

The bootstrap downloads the verified release binary, then runs the Go
installer (`ovnode install`). The previous bash installer is shipped one
release as `install-legacy.sh`.
To answer every setting yourself, run the interactive installer instead:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh) interactive
```

**With no terminal** — a run without one cannot ask, so it needs `-y` to say that is intended. The two flags are `-y/--yes` and `-h/--help`, and everything else is an `OVN_*` variable:

```bash
curl -fsSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh -o install.sh
OVN_NAME=eu-1 OVN_VPN_PORTS=1194,443,8443 OVN_IPV6=1 bash install.sh -y
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `OVN_NAME` | `ovnode` | Node name — must match the panel exactly |
| `OVN_KEY` | generated | API key, minimum 16 characters |
| `OVN_PORT` | `2083` | Sync API port the panel connects to |
| `OVN_VPN_PORTS` | `1194` | VPN ports; the first listens, the rest are redirected to it and listed in every `.ovpn` |
| `OVN_PROTO` | `udp` | `udp` or `tcp` |
| `OVN_TLS` | `selfsigned` | `selfsigned`, `letsencrypt`, `letsencrypt-ip` or `custom` |
| `OVN_TLS_DOMAIN` | — | Domain, for the Let's Encrypt modes |
| `OVN_TLS_KEY`, `OVN_TLS_CERT` | — | File paths, for `OVN_TLS=custom` |
| `OVN_IPV6` | off | `1` adds a ULA pool and an IPv6 route push |
| `OVN_NO_NAT` | off | `1` skips forwarding, NAT and port redirects — you handle them |
| `OVN_QUIET` | off | `1` suppresses progress logs |
| `OVN_REPO` | `anonysec/OVNode` | Pull releases from a fork |


A run with `-y` never prompts and reports its outcome as an exit code, so a script branches on `$?` instead of parsing output. A run *without* `-y` and without a terminal stops and says so, rather than picking answers for you:

```text
0 ok · 1 error · 2 usage error · 3 already installed · 4 not installed
```

Older flag spellings still work but print what replaces them. The installer's own commands are `update`, `recover-update`, `repair-unit`, `uninstall`, `interactive`, `version-script` and `help`; with none given it installs. `bash install.sh help` prints the whole surface.

## 🏁 After it finishes

The install ends with a **Ready — save this login** card holding the node name, the service URL and the API key. The API key is shown there once; `ovnode auth key` reprints it whenever you need it.

**Register the node in the panel.** This is the step people get stuck on. OVManager has to be told the node exists before it can use it.

1. In OVManager, open **Nodes → Add Node**.
2. Paste the **Bundle** from the card into the form. It fills the name, address, port, API key and TLS flag in one go. Typing the fields by hand works too.
3. Turn **TLS on**. The node always serves HTTPS — plain HTTP is not offered, because the API key travels in a header on every request.
4. Save. A green row in the node list means the panel reached the node.

Then **Users → Add User** in the panel, download the `.ovpn` and connect with any OpenVPN client.

If the card shows a private address (`10.x`, `192.168.x`), the server is behind NAT — put its **public** IP in the panel instead. With a cloud firewall (security groups, and so on) open the VPN ports yourself on both UDP and TCP, and the sync API port only from the panel.

**Where things live:**

| Path | What |
| --- | --- |
| `/opt/ovnode` | The installed tree, with its own virtualenv and the `ovnode` manager |
| `/opt/ovnode/.env` | Runtime settings — port, VPN pool, DNS, extra ports, IPv6, runtime user |
| `/var/lib/ovnode/openvpn/server` | `server.conf`, the PKI and the OpenVPN logs |
| `/var/lib/ovnode/openvpn/server/users` | Per-user folders, session markers, usage counters and the hooks |
| `/var/lib/ovnode` | The agent's own data. `DATA_DIR` in `.env` names it |
| `/var/backups` | Backup archives written by `ovnode backup` |

The agent's runtime settings use `OVNODE_*` names and live in `/opt/ovnode/.env`; they are separate from the installer's `OVN_*` variables above. Every one is documented in [.env.example](.env.example). The OpenVPN root is isolated per instance — multiple ovnode instances (or other projects' OpenVPN) never share `/etc/openvpn`.

Fresh managed installs create the `ovnode-vpn` system user/group unless a runtime identity was chosen. `OVN_RUNTIME_USER` and `OVN_RUNTIME_GROUP` select an existing identity at install time; a user-only override uses that user's primary group. Identity-creation failures stop installation.

Updates preserve explicit `OVNODE_RUNTIME_USER`/`OVNODE_RUNTIME_GROUP` settings and existing OpenVPN `user`/`group` directives. Legacy `nobody`/`nogroup` installations are not silently moved to `ovnode-vpn`. They still share their runtime access with other services using that identity; choose a dedicated identity explicitly when migrating. On systems where the legacy group is named `nobody`, retain that group setting rather than assuming `nogroup` exists.

Hooks receive their effective data, log and management paths through OpenVPN `setenv` directives. They do not need access to the private `.env`. Startup repairs policy to root-owned, runtime-group-readable `0640` files and shared session/usage files to `0660`, with setgid directories preserving group access after API writes. The owned hook log uses `0660` and its runtime group on creation and rotation; existing shared log parents and unrelated files are left unchanged. Private keys and profiles remain `0600`.

## 🔌 Sync API

All traffic is panel → node, authenticated with the node's API key in a `key` header, and every response is a `{success, msg, data}` envelope. The panel treats a call as successful only when it gets HTTP 200 with `"success": true`, so handlers report business failures inside the envelope.

| Endpoint | Panel method | Notes |
|---|---|---|
| `GET /sync/health` | Health probe | No auth |
| `GET /sync/status` | `check_node` / `get_node_info` | `cpu_usage`, `memory_usage`, `version`, `cert_expiry` |
| `GET /sync/usage` | `get_usage` | `users` keyed by username (traffic collector), `sessions` carries CN + username keys (panel-side mlogin registry + per-session deltas) |
| `GET /sync/sessions` | `get_sessions` | `live_sessions`, `sessions` (frontend), `stale_markers`, counters, `auth_errors_by_cn` |
| `GET /sync/config` | `read_config` | Live endpoint settings, so the panel can detect drift |
| `POST /sync/config` | `update_config` | `{tunnel_address, protocol, ovpn_port, set_new_setting}`; also accepts `dns1`, `dns2`, `enable_ipv6`, `ipv6_prefix`, `extra_ports` — omitted fields leave the node's values alone |
| `POST /sync/restart` | `restart_vpn` | Restart OpenVPN on the node |
| `POST /sync/renew-cert` | `renew_server_cert` | Renew the server certificate, then restart OpenVPN |
| `POST /sync/user` | `create_user` | `id` optional — falls back to normalized `name` |
| `PUT /sync/user` | `change_user_status` | `activate` / `deactivate`, optional `max_logins` |
| `PUT /sync/user/limit` | `set_user_limit` | `id` may be numeric id or username |
| `POST /sync/users` | `set_user_limits` (bulk) | Many users in one call, cap 500; per-item failures in `data.failed` |
| `PUT /sync/users/{cn}` | panel PKI push | Pushed `cert_pem`/`key_pem` (+ optional `ca_pem`), `max_logins`, `disabled`; writes `state`, `cert.pem`, `key.pem`, `ca.pem` |
| `PUT /sync/pki` | panel PKI bootstrap | Pushed `ca_pem`/`server_cert_pem`/`server_key_pem`; reloads OpenVPN via the management socket |
| `DELETE /sync/user/{uid}` | `delete_user` | NOT_FOUND counts as success so panel cleanup proceeds |
| `POST /sync/user/{uid}/disconnect` | `disconnect_user` | Kills sessions + clears stale markers |
| `POST /sync/user/{uid}/reset-usage` | `reset_user_usage` | Zero the banked counters |
| `GET /sync/download/ovpn/{uid}` | `download_ovpn_client` / `_bytes` | Lazy creation on first download; body starts with `client` |
| `POST /sync/update` | `trigger_update` | Ask the node to run its own self-update |
| `GET /sync/logs` | node log viewer | `level` (default `WARNING`) and `limit` (default 200) |

The full route list lives in `internal/httpapi/contract.json` and is pinned by `internal/httpapi/contract_test.go`.

Identity: the OpenVPN CN is the panel's numeric user id (`str(user.id)`), and the display name is kept in `users/<cn>/name` so usage can be keyed by username, as the panel's traffic collector expects.

Diagnostics without SSH: `GET /sync/logs?level=ERROR` reads the agent's in-memory log buffer, and `GET /sync/status` reports `openvpn_running`, `uptime_seconds`, `errors_1h`, `warnings_1h` and `last_error` alongside the panel-contract keys.

New/changed fields: `GET /sync/status` now includes `update_status` and `crl_days_remaining`; `POST /sync/update` accepts an optional `version` (x.y.z); `authorize` may return 429 (rate limit) or 503 (API key shorter than 16 characters).

### Upgrading

- Permissions are repaired on first start after update.
- Extra-port redirects from older versions may need `iptables -t nat -S PREROUTING` review.

## 🧰 Day-to-day commands With no argument it prints this list and exits — there is no menu, so a provisioning script that invokes it never blocks waiting for input. Twelve verbs; `ovnode help --all` carries every option and the retired names.

Run `sudo bash scripts/smoke-test.sh` on a fresh node to verify the install.

| Command | What it does |
| --- | --- |
| `ovnode status` | Agent, health, version and VPN state. `--all` adds node, mode, port and TLS. |
| `ovnode logs [N\|-f]` | Last N log lines (default 100), or follow live. |
| `ovnode restart` | Restart the node agent. |
| `ovnode restart core` | Restart the OpenVPN server. |
| `ovnode enable \| disable` | Automatic start at boot. |
| `ovnode auth` | Credential state, then the options that apply. |
| `ovnode auth key` | Node name and API key, any time. |
| `ovnode auth rotate` | Generate a new API key. Prints it and the `.env` line to change. |
| `ovnode auth disconnect` | Release the paired panel now — a paired node refuses a second panel for 30 minutes otherwise. |
| `ovnode tls` | Certificate state, then `selfsigned`, `le IP\|DOMAIN` or `custom CERT KEY`. |
| `ovnode backup [--keep N]` | Save state and PKI backups now. |
| `ovnode backup schedule [on\|off\|status]` | Host timer: a daily backup at `03:30`. |
| `ovnode restore [name]` | List data backups, or restore one by name. |
| `ovnode update` | Update through the installer, with a verified snapshot first. Recovers an interrupted update before starting a new one. |
| `ovnode rollback` | Restore the newest pre-update code snapshot. |
| `ovnode config` | Every effective setting and where it comes from. Read-only. |
| `ovnode uninstall [--purge]` | Remove OVNode. Data is kept unless `--purge`. |
| `ovnode info` | Connection details (address, port, protocol, key, certificate). |
| `ovnode edit` | Edit the OpenVPN server configuration. |
| `ovnode edit-env` | Edit the node `.env` file. |

### Multi-instance

Each instance keeps its own app and data directories and command name:

```bash
OVN_INSTANCE=node2 bash install.sh   # or: bash install.sh --instance node2
node2 status
```

Native installs use less memory and CPU on small servers.

### Retired names

These still work, unchanged. Nothing warns — a deprecation line on every nightly backup job is noise, not notice.

| Old | Now |
| --- | --- |
| `ovnode credentials` | `ovnode auth key` |
| `ovnode restart-vpn` | `ovnode restart core` |
| `ovnode auto-backup [on\|off\|status]` | `ovnode backup schedule [on\|off\|status]` |
| `ovnode recover-update` | `ovnode update` — it recovers an interrupted one first |
| `ovnode start` / `ovnode stop` | `ovnode restart` |

### `.env` is yours

The installer writes `.env` once, at install, and **nothing in `ovnode` ever edits it again** — not `ovnode auth rotate`, not `ovnode tls`. Edit it freely; changes take effect on `ovnode restart`. `ovnode config` prints every effective setting and its source.

That is why `ovnode auth rotate` prints the new key and the line to change rather than making the change: a command that quietly rewrote the file would mean the `.env` in your backups is not the one you last edited.
When both `.env` and the process environment define a variable, the `.env`
value wins (cached at startup).

Node data lives at `/var/lib/ovnode`, and `DATA_DIR` in `.env` names it. Older
installs kept it one level down at `/var/lib/ovnode/<name>` — a layout for several
nodes on one host that nothing ever implemented. `ovnode update` moves it up and
repoints `DATA_DIR`; it refuses rather than merging if both directories hold the
same file, and it is a no-op on an install that is already flat.

The API key lives in `.env`, not in the panel. It is printed by the installer and by `ovnode auth key`; neither can be recovered elsewhere, so losing `.env` means re-enrolling the node. The node keeps its own certificate in `/etc/ovnode/tls` (or wherever `SSL_KEYFILE` says) rather than in `/etc/ssl/self-signed`, which is shared with an OVManager panel on the same host.

`ovnode restore` takes a safety copy before it replaces anything, and refuses to continue if it cannot. `ovnode update` and `ovnode uninstall` run the Go installer, so each exists in exactly one place.
`ovnode backup` archives `/var/lib/ovnode` and the OpenVPN PKI (`/var/lib/ovnode/openvpn/server/pki`) into root-only tarballs in `/var/backups`, keeping the newest 14 (`--keep N` changes that). `ovnode update` is stricter still: it snapshots the identity file, the node data directory, the OpenVPN root and the API TLS files before it touches anything, and rolls back if the new release does not come up.

## 📚 Docs

Full documentation is published at **<https://anonysec.github.io/OVManager/>** — OVNode shares the OVManager site.

| Guide | What is in it |
| --- | --- |
| [Adding nodes](https://anonysec.github.io/OVManager/wiki/nodes.html) | Install the agent, register it in the panel, and get the firewall right. |
| [How it works](https://anonysec.github.io/OVManager/wiki/how-it-works.html) | What runs where on a node, where its data lives, and the security model. |
| [CLI reference](https://anonysec.github.io/OVManager/wiki/cli.html) | Every `ovnode` command, and the node installer's flags and `OVN_*` settings. |
| [TLS certificates](https://anonysec.github.io/OVManager/wiki/tls.html) | Self-signed vs Let's Encrypt, renewals, and the node-side certificate. |
| [Troubleshooting](https://anonysec.github.io/OVManager/wiki/troubleshooting.html) | A red node, an unhealthy agent, and no internet through the tunnel. |

In this repository:

- [.env.example](.env.example) — every `OVNODE_*` runtime setting.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability.
- [CHANGELOG.md](CHANGELOG.md) — what changed in each release.

### Manual install (developers)

```bash
git clone https://github.com/anonysec/OVNode.git /opt/ovnode
cd /opt/ovnode
cp .env.example .env   # REQUIRED: set API_KEY, min 16 chars
go build ./cmd/ovnode
./ovnode serve
```

The production installer consumes release binaries (verified against the release SHA256SUMS) only, so a source checkout is a development path rather than a deployment one. Manual mode runs the API alone: TLS (through `ssl_certfile`/`ssl_keyfile` in `.env`), IP forwarding and NAT, the firewall, service supervision and the OpenVPN daemon are yours to configure — the installer does all of that.

## Operating guarantees (Task 12 corrections)

- **Runtime permissions:** dropped-UID hooks can read policy and write accounting/session state, but cannot read private credentials or modify policy; secrets and profiles stay root-only.
- **NAT enrollment/reboot:** native NAT is applied from the owned systemd unit at boot; `VPN_NAT_ENABLED=0`/`1` in `/etc/default/ovnode-nat` records opt-out; legacy enrolled means enrolled, absent file means not enrolled; opted-out nodes perform no NAT writes. Config changes propagate errors instead of false success.
- **Counter/reset rules:** per-session increments are counted once across polls, disconnects, replay, restart, and reset; reset rotates the epoch and preserves live-session offsets; legacy unsigned counter files are accepted as the starting total. A corrupt/unknown-version counter file is an unavailable sample, not zero.
- **Counter-format migration and safe downgrade:** v2 counter JSON is not readable by older binaries; downgrade uses the verified pre-update state snapshot while traffic is quiesced. Never blindly replace binaries across counter formats.

## 📄 License

MIT. See [LICENSE](LICENSE).

OVManager and OVNode are independent repositories released on the same line (currently `2.0.3`). The OVManager installer can install OVNode on the same host; register the node in OVManager under **Nodes → Add Node**. The node never calls the panel — see the OVManager guide [Adding nodes](https://anonysec.github.io/OVManager/wiki/nodes.html).

## Dev builds
Install a rolling dev build: `OVN_VERSION=dev bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh)`. Dev versions look like `dev-YYYYMMDD.N-<sha>`.
