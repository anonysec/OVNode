# OVNode quickstart

OVNode is the VPN server your OVManager panel talks to. Install it on the
machine your users will connect to — the panel's own server is fine, one node
and one panel can share a host.

You need: a Linux server (Debian/Ubuntu recommended) and root.

## 1. Install

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh)
```

The installer asks one question:

```
  OVNode Setup
  ────────────

  1. Install              Recommended
  2. Install with Docker

  0. Exit
```

**1** is the recommended path and asks nothing else. It installs the agent as a
systemd service with safe defaults:

| Setting | Default |
|---|---|
| Node name | `ovnode` |
| Sync API port | `2083` (the next free port if that one is taken) |
| OpenVPN | `1194`/udp |
| TLS | self-signed — encrypted, and the panel's TLS switch goes **on** |
| API key | generated, 64 hex characters |

**2** runs the agent and OpenVPN in one container with host networking, and
needs `/dev/net/tun` (the installer handles it).

To answer every question yourself, run the numbered wizard instead:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh) interactive
```

It walks four steps:

| Step | Question | Beginner answer |
|---|---|---|
| 1/4 Node identity | Node name | `ovnode` — one short word. You type the **same** name in the panel; renaming later orphans the old data, so pick once. |
| | Service port | Enter (`2083`) — this is the panel's API port, not the VPN port. |
| | OpenVPN port(s) | Enter (`1194`). Add `443,8443` for users on restrictive networks — clients then fail over automatically. |
| | API key | Enter — a strong one is generated. |
| 2/4 VPN transport | UDP or TCP | `1` UDP. TCP only where UDP is blocked. |
| 3/4 Deployment | Host or Docker | `1` Host on a normal VPS. |
| 4/4 Certificate | TLS mode | `1` Self-signed. Plain HTTP is not offered. |

Wait for the **Ready — save this login** card, which prints the node name, the
service URL, the API key and an `ovnode://…` bundle.

Unattended installs take the same code path with no questions:

```bash
curl -fsSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh \
  | OVN_NAME=ovnode bash -s -- -y
```

`-y`, `--docker` and `--help` are the only flags. Every other setting is an
`OVN_*` variable (`OVN_NAME`, `OVN_PORT`, `OVN_VPN_PORTS`, `OVN_KEY`,
`OVN_TLS`, …); the older flag spellings still work but print a deprecation
warning. See the README's install table.

## 2. Register the node in the panel

**This is the step that trips people up.** Until the panel knows about the node,
nothing works.

In OVManager, open **Nodes → Add Node**:

1. Paste the **Bundle** from the installer's card. It fills name, address, port,
   API key and TLS in one go.
2. Check the fields against the card. Address must be this server's **public**
   IP — if the card shows `10.x` or `192.168.x`, the box is behind NAT and the
   public address is what the panel needs.
3. Turn **TLS on**. The node always serves HTTPS.
4. Save. A green row means the panel reached the node.

Lost the card? The panel bundle is reprinted any time:

```bash
ovn credentials
```

Then **Users → Add User** in the panel, download the `.ovpn` and connect with
any OpenVPN client.

## 3. Firewall

If `ufw` or `firewalld` is running, the installer opens the ports for you. A
cloud firewall (security groups, Hetzner, …) is not touched — open it yourself:

- the VPN ports, UDP and TCP, from everywhere
- the service port (`2083`/tcp) only from the panel

## Upkeep

```bash
ovn status                  # health, version, TLS certificate expiry
ovn credentials             # node name, API key, panel bundle
ovn logs -f                 # follow the agent log
ovn update                  # newest release; snapshots state first, rolls back on failure
ovn backup                  # data + PKI into /var/backups
ovn restore                 # list backups, then restore one
ovn doctor --fix            # health check; --fix applies safe repairs
```

Stuck? See [troubleshooting.md](troubleshooting.md).
