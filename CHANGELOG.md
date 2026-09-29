# Changelog

## 1.0.0 — 2026-09-29

First public release. One installer, one manager, and one copy of the shell
helpers they share.

**Install**

```bash
bash <(curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh)
```

One question — host service, or Docker — then safe defaults: node `ovnode`,
sync API on `2083`, OpenVPN on `1194/udp`, self-signed TLS and a generated API
key. The install ends with the node name, API key and an `ovnode://` bundle for
**Nodes → Add Node** in the panel.

- Three flags: `-y`/`--yes`, `--docker`, `-h`/`--help`. Every other setting is
  an `OVN_*` variable; the older flag spellings still work and warn.
- Interactive and unattended installs take the same code path, so the two cannot
  configure a machine differently.
- Installs come from a checksum-verified release archive. Nothing is built from
  source.
- `install.sh` carries no copies: it sources `scripts/lib/`, beside the script or
  fetched as a set, and starts only once the whole set is present.
- Installing a node no longer disturbs a panel on the same host, even though
  both keep a certificate in `/etc/ssl/self-signed`.

**Manage**

Every menu item is also a plain command with a stable exit code — `status`,
`credentials`, `logs`, `backup`, `restore`, `auto-backup`, `doctor`, `update`,
`rollback`, `tls`, `completion` and the service controls.

- `ovn credentials` reprints the node name, API key and panel bundle at any
  time; the install summary is no longer the only place they exist.
- `ovn restore` lists data backups and restores one, taking a safety copy first.
- `ovn update` snapshots identity, node data, `/etc/openvpn` and the API TLS
  files before it starts, and rolls back if the new release does not come up.
- `ovn completion` installs shell completion.
- `install.sh version-script` reports which installer was actually run.
- Read-only commands report an unreadable `.env` as an error instead of
  reporting defaults that look like real data.
- `uninstall` keeps data unless `--purge`, and its confirmation defaults to No.
