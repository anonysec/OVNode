# OVNode

The VPN server half of an [OVManager](https://github.com/anonysec/OVManager) deployment: one OpenVPN server, plus the small agent the panel drives it through.

<div align="center">
  <img src=".github/assets/banner.svg" alt="OVNode — the VPN server agent for OVManager" width="820">
  <br><br>

  [![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![CI](https://github.com/anonysec/OVNode/actions/workflows/ci.yml/badge.svg)](https://github.com/anonysec/OVNode/actions/workflows/ci.yml)
  [![Python](https://img.shields.io/badge/python-3.12%2B-3776ab?logo=python&logoColor=white)](pyproject.toml)
  [![Runtime](https://img.shields.io/badge/runtime-systemd%20%7C%20docker-555555)](#-install)
</div>

## 📖 Table of contents

- [What is this?](#-what-is-this)
- [Why this one?](#-why-this-one)
- [Features](#-features)
- [Install](#-install)
- [After it finishes](#-after-it-finishes)
- [Sync API](#-sync-api)
- [Day-to-day commands](#-day-to-day-commands)
- [Docker](#-docker)
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
- **Nothing to migrate.** There is no database. Node state is plain files under `/etc/openvpn` and `/var/lib/ovnode`, which is what makes `ovn backup` a tarball and a restore a file copy.
- **Upgrades that keep your edits.** Hardening directives are appended to an existing `server.conf` rather than replacing it, and an older on-disk layout is migrated when the agent starts, so restoring an old backup just works.
- **A verified identity at all times.** Every panel request carries the node's API key, and the panel is the side that dials — so a node is reachable only by something that already knows the key.

## ✨ Features

### 🔐 OpenVPN, wired end to end
- The agent generates the PKI and `server.conf` on first boot.
- The installer adds IP forwarding, NAT masquerade, port redirects, `ufw`/`firewalld` openings, log rotation and a systemd unit (or a compose file).
- Hardened defaults: ECDSA `prime256v1` PKI, `tls-crypt`, `remote-cert-tls client`, `tls-version-min 1.3` in the generated configuration, AES-GCM, compression off, and CRL enforcement.
- OpenVPN drops privileges to an unprivileged runtime user, and the management interface listens on localhost only behind a password file.
- PKI failures start the agent in diagnostics mode instead of killing it, so you can still reach it to see what went wrong.

### 👤 Users and profiles
- The panel's numeric user id *is* the OpenVPN common name: user `42` gets certificate CN `42`. The display name is kept beside it, so usage can be reported by name.
- One folder per user under `/etc/openvpn/ovnode/users/<cn>/`, holding the name, the state (login limit and disabled flag) and a cached profile.
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
- `ovn doctor` checks the agent, OpenVPN, disk space, the certificate and recent backups, and applies the safe repairs with `--fix`.
- `ovn update` takes a verified snapshot of the identity file, the node data directory, `/etc/openvpn` and the API TLS files, then swaps in the release and restores the snapshot if the new one does not come up healthy.
- `ovn rollback` returns to the previous code tree; `ovn recover-update` cleans up an update interrupted by a reboot or power loss.
- `ovn backup` archives the node data and PKI into root-only tarballs, on demand or through a daily system timer, with retention you set.
- Log rotation, disk-space checks and a stable set of exit codes, so `ovn` is scriptable rather than menu-only.

## 🚀 Install

**Before you start:**

- A Linux server — Debian or Ubuntu recommended. The panel's own server is fine; one node and one panel can share a host.
- Root, or an account with `sudo`.
- A host with systemd for the default install. In a container without systemd, or if you prefer containers, use Docker mode.
- `1194/udp` reachable by your users, and `2083/tcp` reachable from the panel.

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh)
```

The menu asks one question, and the recommended choice asks nothing else:

| Choice | What it does |
| --- | --- |
| **1. Install** | Host service. Node `ovnode`, sync API on `2083`, OpenVPN on `1194/udp`, self-signed TLS, generated API key. |
| **2. Install with Docker** | Agent and OpenVPN in one container with host networking, which needs `/dev/net/tun` (the installer sets it up). |

To answer every setting yourself, run the wizard instead:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh) interactive
```

**Unattended**, for scripts and CI — the three flags are `-y/--yes`, `--docker` and `-h/--help`, and everything else is an `OVN_*` variable:

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

An unattended install never prompts — `-y`, or simply no terminal — and reports its outcome as an exit code, so a script branches on `$?` instead of parsing output:

```text
0 ok · 1 error · 2 usage error · 3 already installed · 4 not installed
```

Older flag spellings still work but print what replaces them. The installer's own commands are `update`, `recover-update`, `repair-unit`, `uninstall`, `interactive`, `version-script` and `help`; with none given it installs. `bash install.sh help` prints the whole surface.

## 🏁 After it finishes

The install ends with a **Ready — save this login** card holding the node name, the service URL, the API key and an `ovnode://…` bundle. The API key is shown there once; `ovn credentials` reprints it whenever you need it.

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
| `/opt/ovnode` | The installed tree, with its own virtualenv and the `ovn` manager |
| `/opt/ovnode/.env` | Runtime settings — port, VPN pool, DNS, extra ports, IPv6, runtime user |
| `/etc/openvpn/server` | `server.conf`, the PKI and the OpenVPN logs |
| `/etc/openvpn/ovnode` | Per-user folders, session markers, usage counters and the hooks |
| `/var/lib/ovnode/<name>` | The agent's own data, under the node's `--name` |
| `/var/backups` | Backup archives written by `ovn backup` |

The agent's runtime settings use `OVNODE_*` names and live in `/opt/ovnode/.env`; they are separate from the installer's `OVN_*` variables above. Every one is documented in [.env.example](.env.example).

## 🔌 Sync API

All traffic is panel → node, authenticated with the node's API key in a `key` header, and every response is a `{success, msg, data}` envelope. The panel treats a call as successful only when it gets HTTP 200 with `"success": true`, so handlers report business failures inside the envelope.

| Endpoint | Panel method | Notes |
|---|---|---|
| `GET /sync/health` | Docker healthcheck | No auth |
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
| `DELETE /sync/user/{uid}` | `delete_user` | NOT_FOUND counts as success so panel cleanup proceeds |
| `POST /sync/user/{uid}/disconnect` | `disconnect_user` | Kills sessions + clears stale markers |
| `POST /sync/user/{uid}/reset-usage` | `reset_user_usage` | Zero the banked counters |
| `GET /sync/download/ovpn/{uid}` | `download_ovpn_client` / `_bytes` | Lazy creation on first download; body starts with `client` |
| `POST /sync/update` | `trigger_update` | Ask the node to run its own self-update |
| `GET /sync/logs` | node log viewer | `level` (default `WARNING`) and `limit` (default 200) |

That is 18 routes: `config.py` (5), `users.py` (8), `system.py` (3) and `stats.py` (2). The same list lives in each route module's docstring, and both copies are pinned against the live router by `tests/test_sync_contract_surface.py`.

Identity: the OpenVPN CN is the panel's numeric user id (`str(user.id)`), and the display name is kept in `users/<cn>/name` so usage can be keyed by username, as the panel's traffic collector expects.

Diagnostics without SSH: `GET /sync/logs?level=ERROR` reads the agent's in-memory log buffer, and `GET /sync/status` reports `openvpn_running`, `uptime_seconds`, `errors_1h`, `warnings_1h` and `last_error` alongside the panel-contract keys.

## 🧰 Day-to-day commands

Every install adds one command, `ovn` (short for `ovnode`). With no argument it opens a numbered menu; every menu item is also a plain command with a stable exit code.

| Command | What it does |
| --- | --- |
| `ovn status` | Agent, health, version and VPN state. `--all` adds node, mode, port and TLS. |
| `ovn credentials` | Node name, API key and the panel bundle, any time. |
| `ovn logs [N\|-f]` | Last N log lines (default 100), or follow live. |
| `ovn backup [--keep N]` | Save state and PKI backups now. |
| `ovn restore [name]` | List data backups, or restore one by name. |
| `ovn auto-backup on \| off \| status` | Host timer: a daily backup at `03:30`. |
| `ovn doctor [--fix]` | Health check across agent, VPN, disk, certificate and backups. |
| `ovn tls` | Show or replace the certificate. |
| `ovn update` | Update through the installer, with a verified snapshot first. |
| `ovn rollback` | Restore the newest pre-update code snapshot. |
| `ovn recover-update` | Recover an interrupted update transaction. |
| `ovn start \| stop \| restart` | Control the node agent service. |
| `ovn restart-vpn` | Restart or reload OpenVPN. |
| `ovn completion` | Install bash completion for `ovn`. |
| `ovn uninstall [--purge]` | Remove OVNode. Data is kept unless `--purge`. |

`ovn restore` takes a safety copy before it replaces anything, and refuses to continue if it cannot. `ovn update` and `ovn uninstall` delegate to the installer, so each exists in exactly one place.

`ovn backup` archives `/var/lib/ovnode` and the OpenVPN PKI (`/etc/openvpn/server/pki`) into root-only tarballs in `/var/backups`, keeping the newest 14 (`--keep N` changes that). `ovn update` is stricter still: it snapshots the identity file, the node data directory, `/etc/openvpn` and the API TLS files before it touches anything, and rolls back if the new release does not come up.

## 🐳 Docker

One container runs both the agent and the OpenVPN daemon. Host networking is used on purpose — no double NAT, honest client IPs, and multi-port without port-mapping edits. The entrypoint enables forwarding and sets up MASQUERADE and the port redirects itself, which is what it needs `CAP_NET_ADMIN` for.

The installer generates a per-node compose file with `--docker`, or you can use the bundled one:

```bash
cp .env.example .env   # set API_KEY at minimum
docker compose up -d
```

All state lives in the `/etc/openvpn` volume, so the container itself is replaceable. `OVNODE_SKIP_OPENVPN=1` runs the agent alone, for debugging.

## 📚 Docs

Full documentation is published at **<https://anonysec.github.io/OVManager/>** — OVNode shares the OVManager site.

| Guide | What is in it |
| --- | --- |
| [Adding nodes](https://anonysec.github.io/OVManager/wiki/nodes.html) | Install the agent, register it in the panel, and get the firewall right. |
| [How it works](https://anonysec.github.io/OVManager/wiki/how-it-works.html) | What runs where on a node, where its data lives, and the security model. |
| [CLI reference](https://anonysec.github.io/OVManager/wiki/cli.html) | Every `ovn` command, and the node installer's flags and `OVN_*` settings. |
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
pip install uv && uv sync
uv run main.py
```

The production installer consumes verified release archives only, so a source checkout is a development path rather than a deployment one. Manual mode runs the API alone: TLS (through `ssl_certfile`/`ssl_keyfile` in `.env`), IP forwarding and NAT, the firewall, service supervision and the OpenVPN daemon are yours to configure — the installer does all of that.

## 📄 License

MIT. See [LICENSE](LICENSE).

Node `1.0.x` pairs with OVManager `1.0.x`, so upgrade both together. The `2.x` line was retired before 1.0.0 — see [CHANGELOG.md](CHANGELOG.md).
