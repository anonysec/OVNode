# OVNode quickstart (3 minutes)

OVNode is the VPN server that your OVManager panel talks to. Install it on
the machine your users will connect to (same server as the panel is fine —
see below).

You need: a Linux server (Debian/Ubuntu recommended), `sudo` access.

## 1. Install

```bash
bash <(curl -sSL https://anonysec.github.io/OVNode/install.sh)
```

Answer the wizard:

| Question | Beginner answer |
|---|---|
| Node name | `node-1` (one short word; you will type the **same** name in the panel — renaming later orphans old data, so pick once) |
| Service port | Enter (`2083` — the panel's API, not the VPN) |
| OpenVPN ports | Enter (`1194`; add `443,8443` for users on restrictive networks) |
| API key | Leave blank — a strong one is generated. **Copy it from the summary.** |
| Mode | `1` Native on a normal VPS. `2` Docker if you prefer containers (needs `/dev/net/tun`, handled automatically). |
| TLS | `3` Self-signed (encrypted; then turn TLS **on** in the panel). Never `5` None over the internet. |

You get a green summary: node name, address, service URL, **API key**.
Keep the key — it is shown once.

One-liner for scripts (same result, no questions):

```bash
curl -sSL https://anonysec.github.io/OVNode/install.sh \
  | sudo bash -s -- install -y --name node-1 --tls selfsigned \
    --api-key "$(openssl rand -hex 32)"
```

## 2. Register in the panel

In OVManager: **Nodes → Add Node** (or paste the printed `ovnode://`
bundle — it fills everything):

* Name = node name, **exactly** (`node-1`)
* Address = this server's **public** IP (if the summary shows `10.x` /
  `192.168.x`, the box is behind NAT — use the public IP)
* Port `2083`, API key from step 1, TLS on (self-signed) / off (only if None)

Green row = connected. Then Users → Add User → download `.ovpn` → connect
with any OpenVPN client.

## 3. Firewall

`ufw`/`firewalld` rules are added for you. With a **cloud firewall**
(AWS security groups, Hetzner, …) open yourself: `1194` UDP+TCP (and any
extra VPN ports) from everywhere, `2083`/TCP only from the panel.

## Upkeep

```bash
bash <(curl -sSL https://anonysec.github.io/OVNode/install.sh) status    # health, TLS cert expiry
bash <(curl -sSL https://anonysec.github.io/OVNode/install.sh) update    # backs up /etc/openvpn first
```

Stuck? See [troubleshooting](troubleshooting.md).
