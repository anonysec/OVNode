# OVNode

OpenVPN node agent for [OVManager](https://github.com/anonysec/OVManager). Manages the OpenVPN server, PKI, per-user configs, traffic accounting, and multi-login enforcement.

## Features

- **Modern OpenVPN defaults** — ECDSA (secp384r1) PKI, `tls-crypt`, TLS ≥ 1.2, ECDHE (no static DH), GCM ciphers, CRL enforcement, `remote-cert-tls` verification on both sides.
- **Management interface** — wired up and restricted to the runtime user so session takeover (`max_logins=1`) and disconnects work reliably.
- **Working client configs** — generated `.ovpn` files embed the `tls-crypt` key inline (a missing key previously made every client handshake fail).
- **Idempotent upgrades** — existing installs get new hardening directives appended on boot without clobbering admin edits; missing `dh` files are auto-replaced with `dh none`.
- **Multi-login enforcement** — per-user device limits enforced at connect time (takeover for 1, reject N+1, unlimited for 0), dynamic-IP aware.
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

See `install.sh --help` for TLS modes, Docker, and non-interactive (`-y`) installs.

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

## OpenVPN tuning (env vars)

All optional — see `.env.example`:

| Variable | Default | Purpose |
|---|---|---|
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

MIT
