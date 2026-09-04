# OVNode troubleshooting

## Panel shows the node red

1. Address = public IP/hostname (`10.x`/`192.168.x` only works on a shared private network).
2. Port `2083` = service port, not `1194` (VPN).
3. API key copied exactly (no spaces). Minimum 16 characters.
4. TLS switch in the panel matches the node: self-signed/LE → **on**,
   None → off.
5. Node name matches `--name` exactly.
6. From the panel server: `curl -sk https://NODE-IP:2083/sync/health`
   should print `{"status":"ok"}`. If not, it is network/firewall, not
   the panel. Cloud security groups are the usual cause (`2083`/tcp from
   the panel IP).

## `status` says unhealthy / API unreachable locally

```bash
sudo bash install.sh status                 # summary + health
curl -sk https://127.0.0.1:2083/sync/health # expect {"status":"ok"}
sudo journalctl -u ovnode -f                # native logs
docker logs -f ovnode                       # docker logs
```

* `/dev/net/tun` missing (Docker): the compose file mounts it; on odd
  kernels run `modprobe tun` on the host.
* After changing ports/TLS, `update` or reinstall with the same `--name`
  (data in `/etc/openvpn` + `/var/lib/ovnode` is kept).

## VPN connects but no internet

Native: `systemctl status ovnode-nat` (MASQUERADE + port redirects) and
`sysctl net.ipv4.ip_forward` (= 1). Docker: container needs
`CAP_NET_ADMIN` (in the shipped compose file). External nftables/cloud
firewalls can still block forwarding.

## Let's Encrypt failures

* Port `80` must be free and the domain must resolve to this server
  (`Port 80 is busy` / DNS error otherwise). Use `--tls selfsigned`
  to get going, switch later.
* `letsencrypt-ip` certificates live ~6 days by design — check `status`
  for expiry; prefer a domain for long-lived certs.

## Reinstall / rename warnings

* Reinstall with the **same** `--name` to keep users/sessions (new name =
  new empty data dir, old one orphaned on disk).
* `uninstall` keeps data; add `--purge` to delete it.
* `update` backs up `/etc/openvpn` first and never touches it otherwise.
