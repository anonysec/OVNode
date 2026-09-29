# OVNode troubleshooting

## The panel shows the node red

1. Address = public IP or hostname. `10.x` / `192.168.x` only works on a shared
   private network.
2. Port is the **service** port (`2083`), not the VPN port (`1194`).
3. API key copied exactly, no spaces. Minimum 16 characters. Reprint it with
   `ovn credentials` rather than retyping it.
4. The panel's TLS switch matches the node: self-signed or Let's Encrypt → **on**.
5. Node name matches `OVN_NAME` (default `ovnode`) exactly.

From the panel server, the node should answer:

```bash
curl -sk https://NODE-IP:2083/sync/health     # expect {"status":"ok"}
```

If that fails, it is network or firewall, not the panel. Cloud security groups
are the usual cause — `2083`/tcp open from the panel's IP.

## `ovn status` says unhealthy, or the API is unreachable locally

```bash
ovn status                                  # summary + health
curl -sk https://127.0.0.1:2083/sync/health # expect {"status":"ok"}
journalctl -u ovnode -f                     # host logs
docker logs -f ovnode-<node name>           # docker logs
```

* `/dev/net/tun` missing in Docker: the compose file mounts it; on odd kernels
  run `modprobe tun` on the host.
* After changing ports or TLS, run `ovn update`, or reinstall with the same
  `OVN_NAME`. The data in `/etc/openvpn` and `/var/lib/ovnode` is kept.
* `ovn doctor --fix` checks the agent, OpenVPN, disk space, the certificate and
  recent backups, and applies the safe repairs.

## VPN connects but there is no internet

Host install: `systemctl status ovnode-nat` (masquerade and port redirects) and
`sysctl net.ipv4.ip_forward` should be `1`. Docker: the container needs
`CAP_NET_ADMIN`, which the shipped compose file grants. An external nftables or
cloud firewall can still block forwarding.

## Let's Encrypt failures

* Port `80` must be free, and the domain must resolve to this server, or you get
  `Port 80 is busy` or a DNS error. Use the self-signed default to get going and
  switch later.
* The Let's Encrypt **IP** mode issues a short-lived certificate by design —
  check expiry in `ovn status`, and use a domain for long-lived certs.

## Reinstall and rename

* Reinstall with the same `OVN_NAME` to keep users and sessions. A new name
  means a new, empty data directory, and the old one is orphaned on disk.
* `ovn uninstall` keeps data; `ovn uninstall --purge` deletes it. Both ask
  first, and the prompt defaults to No.
* `ovn update` snapshots state first and rolls back on failure, so a bad release
  does not need a manual restore.
* Need the node's identity again after a reinstall or a lost card?
  `ovn credentials` prints the name, the API key and the panel bundle.
