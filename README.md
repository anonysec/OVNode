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
- **Local multi-login enforcement** — per-user device limits enforced at connect time (takeover for 1, reject N+1, unlimited for 0), dynamic-IP aware. Cross-node policy stays panel-side: OVManager aggregates `/sync/sessions` from every node and can disconnect anywhere via `/sync/user/{uid}/disconnect`.
- **Optional IPv6** — ULA pool + route push when enabled (`OVNODE_ENABLE_IPV6=1`).

## Install

```bash
bash <(curl -sSL https://anonysec.github.io/OVNode/install.sh)
```

Common flags:

```bash
bash <(curl -sSL URL) \
  --name eu-1 --port 2083 --vpn-port 1194 \
  --api-key "$(openssl rand -hex 32)" \
  --ipv6 --tls-none
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

```bash
bash <(curl -sSL URL) --docker
```

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
| `OVNODE_MAX_CLIENTS` | `100` | Connection cap |
| `OVNODE_ENABLE_IPV6` / `OVNODE_IPV6_PREFIX` | `0` / `fd42:42:42:42::/64` | IPv6 support |

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
