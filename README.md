# OVNode

The VPN server half of an [OVManager](https://github.com/anonysec/OVManager)
deployment: the OpenVPN node agent the panel drives over a private `/sync` API.

<div align="center">
  <img src=".github/assets/banner.svg" alt="OVNode — the VPN server agent for OVManager" width="820">
  <br><br>

  [![Version](https://img.shields.io/badge/version-2.0.18-blue)](CHANGELOG.md)
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![CI](https://github.com/anonysec/OVNode/actions/workflows/ci.yml/badge.svg)](https://github.com/anonysec/OVNode/actions/workflows/ci.yml)
  [![Go](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)](go.mod)
</div>

## What it is

One node = one OpenVPN server (UDP, TCP, or both), its PKI, and a small Go
agent. The panel owns users and policy; the node enforces them at connect
time and reports usage back. State is plain files — there is no database on
the node.

**2.0.0 is the first supported release.** Pre-2.0.0 installations are not
upgradable; the schema and state formats were reset.

## Requirements

- Linux with systemd, root
- OpenVPN 2.6+ and easy-rsa 3
- 512 MB RAM, 200 MB disk (plus logs)
- Inbound: the API port from the panel, the VPN port(s) from users

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/anonysec/OVNode/main/internal/assets/install.sh -o install.sh
bash install.sh            # interactive: node name, ports, protocol, TLS and SANs
bash install.sh -y         # unattended defaults (udp/1194, self-signed)
```

The bootstrap downloads the release binary, verifies it against
`SHA256SUMS`, then runs the Go installer. The interactive installer asks for
the node name, API port/key, VPN ports, protocol, TLS method and (for a
self-signed API certificate) the SAN list. The summary prints the certificate
PEM and its SHA-256 fingerprint for pinning.

`VpnPorts` defaults to 1194; choose a port nothing else is using. 443 is a
common web-server port, so use it only when it is free. For a second instance
on the same host:

```bash
Instance=node2 VpnPorts=1194 ApiPort=2084 bash install.sh -y
# or: bash install.sh --instance node2 ...
```

### Install-time settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `Instance` | `ovnode` | Selects `/opt/<name>`, `/var/lib/<name>`, `/var/log/<name>`, `<name>.service` |
| `ApiPort` | `2083` | Panel-to-node API port |
| `ApiKey` | generated | Shared secret, minimum 16 characters |
| `VpnPorts` | `1194` | Primary port, then extra ports (e.g. `8443`); pick a free port |
| `Proto` | `udp` | `udp`, `tcp`, or `both` |
| `VpnNetwork` | derived | VPN pool base address (default `10.66.<pair>.0` /23) |
| `Ipv6` | off | `1` adds a ULA pool and an IPv6 route push |
| `TlsMethod` | `selfsigned` | `selfsigned`, `letsencrypt`, `letsencrypt-ip`, `custom` |
| `PanelIp` | — | Restrict `/sync` callers to this IP/CIDR |
| `RuntimeUser` / `RuntimeGroup` | `nobody` / `nogroup` | Identity OpenVPN drops to |
| `NoNat` | off | `1` skips forwarding, NAT and port redirects |
| `Version` | `latest` | Pin a release |
| `Repo` | `anonysec/OVNode` | Release source |

All names are accepted as flags too (`--instance`, `--port`, `--proto`, …).

## Protocols

`Proto=both` runs **two** OpenVPN processes on the same port, one UDP and one
TCP, from one agent:

- Each protocol owns `server/<proto>/server.conf`, its status file, PID, log
  and management socket. The PKI, `tls.key`, `ccd` and client template are
  shared.
- The instance owns a /23: UDP uses the first /24, TCP the second, so the two
  tun devices never share a subnet. NAT covers the /23 once.
- Every client profile carries a `<connection>` block per protocol and port,
  so one `.ovpn` works on networks that block UDP and on networks that block
  TCP. See [ISP-COMPAT.md](ISP-COMPAT.md).

## Where things live

```
/opt/<instance>/
├── ovnode-server          the agent
├── <instance>             operator CLI
├── install.sh, ovnode.sh, lib.sh
├── .env                   0600
└── VERSION

/var/lib/<instance>/
├── openvpn/server/
│   ├── pki/               CA, server cert, CRL
│   ├── easy-rsa/
│   ├── tls.key            tls-crypt
│   ├── mgmt-pass
│   ├── client-common.txt
│   ├── udp/, tcp/         server.conf, status.log, ovnode.pid, openvpn.log
├── users/<cn>/            name, state, cert.pem, key.pem, ca.pem, client.ovpn
├── sessions/, usage/
└── state/                 pairing.json, openvpn.json

/var/log/<instance>/       hook-events.log, agent log
/etc/systemd/system/<instance>.service, <instance>-nat.service
/etc/default/<instance>-nat
/etc/cron.d/<instance>-purge
/etc/logrotate.d/<instance>
/etc/sysctl.d/99-<instance>.conf
/var/backups/<instance>-*
```

Every path is derived from `Instance`; two instances never share a file.

## `.env`

Twelve keys, written by the installer, mode 0600:

```bash
Instance=ovnode
DataDir=/var/lib/ovnode
OpenVpnRoot=/var/lib/ovnode/openvpn
LogDir=/var/log/ovnode
ApiPort=2083
ApiKey=
ApiAllowedCidrs=
TlsCertFile=
TlsKeyFile=
RuntimeUser=nobody
RuntimeGroup=nogroup
LogLevel=info
```

`DataDir`, `OpenVpnRoot` and `LogDir` are derived from `Instance` when empty.
`TlsCertFile`/`TlsKeyFile` override the node PKI's server certificate for the
API. `LogLevel` accepts `debug`, `info`, `warn`, `error`.

**OpenVPN tuning is not in `.env`.** It is `state/openvpn.json`, managed from
the panel: protocol, port, extra ports, max clients, keepalive, redirect,
DNS, routes, IPv6, MTU/mssfix, cipher preference, TLS floor, renegotiation,
idle timeout and verbosity. The node validates every value, regenerates the
configuration and reloads or restarts.

## Day to day

| Command | What it does |
| --- | --- |
| `ovnode status` | Service, VPN children, certificate and health |
| `ovnode info` | Connection details and certificate |
| `ovnode restart` | Restart the agent (and its OpenVPN children) |
| `ovnode restart core` | Restart only the agent, which respawns OpenVPN |
| `ovnode logs [n] [-f]` | Journal tail |
| `ovnode auth key` | Show the API key and certificate |
| `ovnode auth rotate` | Print a new key and the line to change |
| `ovnode backup` / `restore` | State + PKI tarballs in `/var/backups` |
| `ovnode update` / `rollback` | Staged update with automatic failover |
| `ovnode tls` | Certificate status and replacement |
| `ovnode edit` | Edit a generated `server.conf` (settings win on the next change) |
| `ovnode uninstall` | Stop, remove; `--purge` removes data too |

`ovnode update` resolves `latest` itself; pin with `ovnode update -v 2.0.0`.

## Security

- ECDSA P-256 PKI, `tls-crypt`, `tls-version-min 1.3` (or 1.2 for older
  clients), `remote-cert-tls client`, CRL enforcement, AES-GCM/ChaCha20,
  compression off.
- API key: at least 16 characters (32+ recommended), constant-time compare;
  per-IP and global rate limits; failed-auth blocking.
- The API is TLS-only. A missing or unreadable certificate is fatal — there is
  no plaintext fallback.
- Single-panel lease: a node is paired with one panel at a time.
- Hooks run as the dropped UID and receive only non-secret settings.

## Panel API

Every route is under `/sync` and requires the `key` header. The important
ones for operators:

- `GET /sync/health` — version, certificate expiry, uptime (no auth)
- `GET /sync/status` — live sessions, limits, node health
- `GET /sync/usage` — per-user counters and epochs
- `GET|POST /sync/config` — effective OpenVPN settings and a typed patch
- `POST /sync/user`, `PUT /sync/user`, `DELETE /sync/user/{uid}`
- `GET /sync/download/ovpn/{uid}` — a user's profile
- `GET /sync/backup` — PKI + state archive

## Troubleshooting

- `ovnode status` first: service, both protocols, certificate.
- `journalctl -u <instance> -n 100` and `/var/log/<instance>/hook-events.log`.
- A client that connects but cannot reach the internet: check
  `net.ipv4.ip_forward`, the NAT unit (`<instance>-nat.service`) and the
  cloud firewall for both UDP and TCP.
- A profile that fails on one ISP: try the other protocol; `Proto=both` gives
  both in one profile.

## Links

- [ISP compatibility](ISP-COMPAT.md) — MCI/MTN behaviour and the `both` setup
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [OVManager](https://github.com/anonysec/OVManager) — the panel
