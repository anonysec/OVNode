# OVNode

OpenVPN node agent for [OVManager](https://github.com/anonysec/OVManager). Manages the OpenVPN server, PKI, per-user configs, traffic accounting, and multi-login enforcement — implementing exactly the sync API OVManager's panel expects.

## OVManager ⇄ OVNode API

Every endpoint maps 1:1 to a method of the panel's `NodeRequests` client. Auth: the panel sends the node API key in the `key` header; responses are `{success, msg, data}` envelopes.

| Endpoint | Panel method | Notes |
|---|---|---|
| `GET /sync/health` | Docker healthcheck | No auth |
| `GET /sync/status` | `check_node` / `get_node_info` | `cpu_usage`, `memory_usage`, `version`, `cert_expiry` |
| `GET /sync/usage` | `get_usage` | `users` keyed by username (traffic collector), `sessions` carries CN + username keys (panel-side mlogin registry + per-session deltas) |
| `GET /sync/sessions` | `get_sessions` | `live_sessions`, `sessions` (frontend), `stale_markers`, counters, `auth_errors_by_cn` |
| `POST /sync/config` | `update_config` | `{tunnel_address, protocol, ovpn_port, set_new_setting}` |
| `POST /sync/user` | `create_user` | `id` optional — falls back to normalized `name` |
| `PUT /sync/user` | `change_user_status` | `activate` / `deactivate`, optional `max_logins` |
| `PUT /sync/user/limit` | `set_user_limit` | `id` may be numeric id or username |
| `DELETE /sync/user/{uid}` | `delete_user` | NOT_FOUND counts as success so panel cleanup proceeds |
| `POST /sync/user/{uid}/disconnect` | `disconnect_user` | Kills sessions + clears stale markers |
| `GET /sync/download/ovpn/{uid}` | `download_ovpn_client` | Lazy creation on first download; body starts with `client` |

Identity: the OpenVPN CN is the panel's numeric user id (`str(user.id)`); the display name is kept in `uid_map.json` so usage reports can be keyed by username, as the panel's traffic collector expects.

**The node never calls the panel.** All communication is panel → node, authenticated by the node API key (over TLS when enabled). Nodes don't store the panel's address, so you can move or replace the panel at any time — just re-add the nodes with the same address, name and API key.

## Features

- **Modern OpenVPN defaults** — ECDSA (secp384r1) PKI, `tls-crypt`, TLS ≥ 1.2, ECDHE (no static DH), GCM ciphers, CRL enforcement, `remote-cert-tls` verification on both sides.
- **Management interface** — wired up and restricted to the runtime user so session takeover (`max_logins=1`) and disconnects work reliably.
- **Working client configs** — generated `.ovpn` files embed the `tls-crypt` key inline.
- **Idempotent upgrades** — existing installs get new hardening directives appended on boot without clobbering admin edits; missing `dh` files are auto-replaced with `dh none`.
- **Local multi-login enforcement** — per-user device limits enforced at connect time (takeover for 1, reject N+1, unlimited for 0). Cross-node policy stays panel-side: OVManager aggregates `/sync/sessions` from every node and can disconnect anywhere via `/sync/user/{uid}/disconnect`.
- **Dynamic-IP safe sessions** — session identity is CN + VPN pool IP and enforcement kills target the management client id, so users whose real IP changes on every reconnect (mobile/CGNAT) are tracked and limited correctly.
- **Multi-port** — one OpenVPN instance reachable on several ports (`--vpn-ports 1194,443,8443`): extra ports are redirected to the listener via iptables, and every `.ovpn` lists all ports as `remote` lines for automatic failover when an ISP blocks one.
- **Optional IPv6** — ULA pool + route push when enabled (`OVNODE_ENABLE_IPV6=1`).

## Install

```bash
bash <(curl -sSL https://anonysec.github.io/OVNode/install.sh)
```

Common flags:

```bash
bash <(curl -sSL URL) \
  --name eu-1 --port 2083 --vpn-ports 1194,443,8443 \
  --api-key "$(openssl rand -hex 32)" \
  --ipv6 --tls none
```

See `install.sh --help` for TLS modes, Docker, and non-interactive (`-y`) installs. Use the same `--name` and `--api-key` when adding the node in the panel (Nodes → Add Node).

## Update / Uninstall

```bash
# Update (backs up data + PKI first)
bash <(curl -sSL URL) update

# Uninstall — data kept unless --purge
bash <(curl -sSL URL) uninstall
bash <(curl -sSL URL) --purge uninstall
```

## Docker

One container runs both the sync agent **and** the OpenVPN daemon, supervised by the entrypoint: OpenVPN is started as soon as the agent has generated `server.conf` (first boot included) and is restarted with backoff if it ever crashes — without taking the API down. Host networking is used on purpose (no double NAT, honest client IPs, multi-port without port-mapping edits); the entrypoint enables forwarding and sets up MASQUERADE/multi-port NAT itself via `CAP_NET_ADMIN`.

Via installer (generates a per-node compose file):

```bash
bash <(curl -sSL URL) --docker
```

Or manually with the bundled compose file:

```bash
cp .env.example .env   # set API_KEY at minimum
docker compose up -d
```

All state (PKI + `ovnode/` store) lives in the `/etc/openvpn` volume — the container is fully replaceable. `OVNODE_SKIP_OPENVPN=1` runs the agent alone (debugging).

## Configuration (env vars)

All optional except `API_KEY` — see `.env.example`:

| Variable | Default | Purpose |
|---|---|---|
| `SERVICE_PORT` | `2083` | Sync API port the panel connects to |
| `API_KEY` | — | Shared secret with the panel (min 16 chars) |
| `NODE_NAME` | `node-1` | Must match the node name registered in the panel |
| `OVNODE_RUNTIME_USER` / `OVNODE_RUNTIME_GROUP` | `nobody` / `nogroup` | OpenVPN privilege drop |
| `OVNODE_MANAGEMENT_PORT` | `7505` | Local management interface |
| `OVNODE_VPN_NETWORK` / `OVNODE_VPN_NETMASK` | `10.8.0.0` / `255.255.255.0` | Client pool |
| `OVNODE_VPN_DNS1` / `OVNODE_VPN_DNS2` | `1.1.1.1` / `8.8.8.8` | DNS pushed to clients |
| `OVNODE_EXTRA_PORTS` | — | Extra VPN ports listed in every `.ovpn` (redirected to `OPENVPN_PORT` by the installer's NAT unit) |
| `OVNODE_MAX_CLIENTS` | `100` | Connection cap |
| `OVNODE_ENABLE_IPV6` / `OVNODE_IPV6_PREFIX` | `0` / `fd42:42:42:42::/64` | IPv6 support |

## On-disk layout

All node state lives in two places — backup/export is just these two paths:

```
/etc/openvpn/
├── server/              # OpenVPN native: server.conf, PKI (CA/certs/CRL), logs
└── ovnode/              # everything OVNode manages
    ├── users/<cn>/      # ONE folder per user
    │   ├── name         #   panel username
    │   ├── limit        #   max simultaneous logins (0 = unlimited)
    │   ├── disabled     #   marker — exists = connections rejected
    │   └── client.ovpn  #   cached profile (regenerated on demand)
    ├── sessions/        # live-session markers (runtime state)
    └── scripts/         # installed connect/disconnect hooks
```

Pre-existing installs with the old scattered layout (`clients/`, `limits/`, `disabled/`, `ovnode-active/`, `uid_map.json`) are migrated automatically on the next agent start — restoring an old backup onto a current build also just works.

## Diagnostics

- **`GET /sync/logs?level=WARNING&limit=200`** — recent node log records (in-memory ring buffer), so a node can be debugged without SSH: `curl -H "key: $API_KEY" https://node:2083/sync/logs?level=ERROR`
- **`GET /sync/status`** also reports `openvpn_running`, `uptime_seconds`, `errors_1h`, `warnings_1h` and `last_error`.
- **`GET /sync/usage`** additionally returns `totals` — lifetime bytes per user (completed sessions banked by the disconnect hook + live traffic). The panel-contract keys (`users`, `sessions`) are unchanged.
- All errors come back in the `{success, msg, data}` envelope; unhandled ones carry a `ref=<id>` that links to the full traceback in `data/app.log` / `journalctl -u ovnode`.

## Manual Install

```bash
git clone https://github.com/anonysec/OVNode.git /opt/ovnode
cd /opt/ovnode
cp .env.example .env  # edit with your settings
pip install uv && uv sync
uv run main.py
```

## License

Copyright (c) 2025 anonysec. All rights reserved. See [LICENSE](LICENSE).
