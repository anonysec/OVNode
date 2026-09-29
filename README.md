# OVNode

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

OVNode is the VPN-node half of [OVManager](https://github.com/anonysec/OVManager):
one OpenVPN server, plus the small API agent the panel drives it through.
It owns the PKI, the client profiles, the traffic counters and the per-user
login limits.

You install it on every server that should carry VPN traffic, then register that
server in the panel once. After that the panel is in charge — it creates users,
sets limits, reads traffic and restarts OpenVPN. **The node never calls the
panel**: it does not store the panel's address, so the panel can be moved or
replaced without touching any node.

Node `1.0.x` pairs with OVManager `1.0.x`, so upgrade both together. The `2.x`
line was retired before 1.0.0 — see [CHANGELOG.md](CHANGELOG.md).

## Install

Run this as root on the VPN server — the panel's own server is fine:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh)
```

The menu asks one question:

| Choice | What it does |
|---|---|
| **1. Install** | Host service. Node `ovnode`, sync API on `2083`, OpenVPN on `1194/udp`, self-signed TLS, generated API key. |
| **2. Install with Docker** | Agent + OpenVPN in one container, host networking. |

The install ends with a **Ready — save this login** card holding the node name,
the service URL, the API key and an `ovnode://…` bundle. The API key is shown
there once; `ovn credentials` reprints it whenever you need it.

### Register the node in the panel

This is the step people get stuck on. OVManager has to be told the node exists
before it can use it.

1. In OVManager, open **Nodes → Add Node**.
2. Paste the **Bundle** from the card into the form. It fills the name, address,
   port, API key and TLS flag in one go. Typing the fields by hand works too.
3. Turn **TLS on**. The node always serves HTTPS — plain HTTP is not offered.
4. Save. A green row in the node list means the panel reached the node.

Then **Users → Add User**, download the `.ovpn` and connect with any OpenVPN
client. Full walkthrough: [docs/quickstart.md](docs/quickstart.md).

If the card shows a private address (`10.x`, `192.168.x`), the server is behind
NAT — put its public IP in the panel instead. With a cloud firewall (security
groups, Hetzner, …) open the VPN ports yourself, and the sync API port only from
the panel.

### Unattended installs

There are three flags: `-y`/`--yes`, `--docker`, `-h`/`--help`. Every other
setting is an `OVN_*` variable. Older flag spellings still work but print a
deprecation warning.

```bash
curl -fsSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh -o install.sh
OVN_NAME=eu-1 OVN_VPN_PORTS=1194,443,8443 OVN_IPV6=1 bash install.sh -y
```

| Variable | Default | Meaning |
|---|---|---|
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
| `OVN_REPO` | `anonysec/OVNode` | Pull releases from a fork |

An unattended install never prompts — `-y`, or simply no terminal — and reports
its outcome as an exit code, so a script branches on `$?` instead of parsing
output:

```
0 ok · 1 error · 2 usage error · 3 already installed · 4 not installed
```

The installer's own commands are `update`, `recover-update`, `repair-unit`,
`uninstall`, `interactive`, `version-script` and `help`; with none given it
installs. Everything day-to-day is the manager, `ovn`. `bash install.sh help`
prints the whole surface.

## What you get

- **OpenVPN wired up end to end** — the agent generates the PKI and
  `server.conf` on first boot; the installer adds IP forwarding, NAT
  masquerade, port redirects, ufw/firewalld openings, log rotation and a
  systemd unit (or a compose file).
- **Modern defaults** — ECDSA `prime256v1` PKI, `tls-crypt`, TLS 1.3 minimum,
  ECDHE with no static DH parameters, AES-GCM, compression off, CRL
  enforcement and `remote-cert-tls client`. OpenVPN drops privileges to an
  unprivileged runtime user.
- **Profiles that work** — generated `.ovpn` files embed the `tls-crypt` key
  inline, are created owner-only and written atomically.
- **Local login limits** — the connect hook enforces `max_logins` at connect
  time: `1` takes over the old session, `N` rejects the N+1th, `0` is
  unlimited. Session identity is CN plus VPN pool IP, so users whose real
  address changes on every reconnect are still counted and limited correctly.
  Cross-node policy stays in the panel.
- **Traffic that survives reconnects** — the disconnect hook banks each
  session's final byte counters, so `/sync/usage` reports lifetime totals per
  user.
- **Multi-port** — one OpenVPN instance reachable on several ports. Every
  profile lists all of them as `remote` lines, so clients fail over when an ISP
  blocks one.
- **Upgrades that keep your edits** — new hardening directives are appended to
  an existing `server.conf` rather than replacing it, and the older on-disk
  layout is migrated on agent start, so restoring an old backup just works.

## Day-to-day

Every install adds one command, `ovn` (short for `ovnode`). With no argument it
opens a numbered menu; every menu item is also a plain command with a stable
exit code:

```bash
ovn status                  # agent, health, version, VPN state  (--all for more)
ovn credentials             # node name, API key and panel bundle, any time
ovn logs -f                 # last 100 lines, or follow
ovn backup                  # data + PKI archive (--keep N, default 14)
ovn restore                 # list backups; `ovn restore <name>` restores one
ovn auto-backup on          # daily backup timer (03:30)
ovn doctor --fix            # health check: agent, VPN, disk, cert, backups
ovn update                  # pull the newest release (backs up first)
ovn rollback                # undo the last update
ovn tls                     # show or replace the certificate
ovn start|stop|restart      # control the agent service
ovn restart-vpn             # restart OpenVPN
ovn completion              # bash completion for ovn
ovn uninstall [--purge]     # remove it; data is kept unless --purge
```

`ovn restore` takes a safety copy before it replaces anything, and refuses to
continue if it cannot. `ovn update` and `ovn uninstall` delegate to the
installer, so each exists in exactly one place.

There is no database. Node state is plain files:

```
/etc/openvpn/server/     server.conf, PKI (CA, certs, CRL), logs
/etc/openvpn/ovnode/     users/<cn>/{name,state,client.ovpn}, sessions/, usage/, scripts/
/var/lib/ovnode/<name>/  agent data
```

`ovn backup` archives `/var/lib/ovnode` and the OpenVPN PKI
(`/etc/openvpn/server/pki`) into root-only tarballs in `/var/backups`, keeping
the newest 14 (`--keep N`). `ovn restore` lists them and unpacks one after
taking a safety copy. `ovn update` is stricter still: it takes a verified
snapshot of the identity file, the node data directory, `/etc/openvpn` and the
API TLS files before it touches anything, and rolls back if the new release
does not come up.

Runtime settings for the agent live in `/opt/ovnode/.env` and use `OVNODE_*`
names (port, VPN pool, DNS, extra ports, IPv6, runtime user). These are separate
from the installer's `OVN_*` variables above. Every one is documented in
[.env.example](.env.example).

## Sync API

All traffic is panel → node, authenticated with the node's API key in a `key`
header, and every response is a `{success, msg, data}` envelope. The panel
treats a call as successful only when it gets HTTP 200 with `"success": true`,
so handlers report business failures inside the envelope.

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

That is 18 routes: `config.py` (5), `users.py` (8), `system.py` (3) and
`stats.py` (2). The same list lives in each route module's docstring, and both
copies are pinned against the live router by
`tests/test_sync_contract_surface.py`.

Identity: the OpenVPN CN is the panel's numeric user id (`str(user.id)`), and
the display name is kept in `users/<cn>/name` so usage can be keyed by
username, as the panel's traffic collector expects.

Diagnostics without SSH: `GET /sync/logs?level=ERROR` reads the agent's
in-memory log buffer, and `GET /sync/status` reports `openvpn_running`,
`uptime_seconds`, `errors_1h`, `warnings_1h` and `last_error` alongside the
panel-contract keys.

## Docker

One container runs both the agent and the OpenVPN daemon. Host networking is
used on purpose — no double NAT, honest client IPs, and multi-port without
port-mapping edits. The entrypoint enables forwarding and sets up MASQUERADE and
the port redirects itself, which is what it needs `CAP_NET_ADMIN` for.

The installer generates a per-node compose file with `--docker`, or you can use
the bundled one:

```bash
cp .env.example .env   # set API_KEY at minimum
docker compose up -d
```

All state lives in the `/etc/openvpn` volume, so the container itself is
replaceable. `OVNODE_SKIP_OPENVPN=1` runs the agent alone, for debugging.

### Manual install (developers)

```bash
git clone https://github.com/anonysec/OVNode.git /opt/ovnode
cd /opt/ovnode
cp .env.example .env   # REQUIRED: set API_KEY, min 16 chars
pip install uv && uv sync
uv run main.py
```

Manual mode runs the API only. TLS (via `ssl_certfile`/`ssl_keyfile` in
`.env`), IP forwarding and NAT, the firewall and any service supervision are
yours to configure — the installer does all of that. So is the OpenVPN daemon.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Docs

- [docs/quickstart.md](docs/quickstart.md) — first run, step by step
- [docs/how-it-works.md](docs/how-it-works.md) — what runs where, and why
- [docs/troubleshooting.md](docs/troubleshooting.md) — when the node shows red
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
