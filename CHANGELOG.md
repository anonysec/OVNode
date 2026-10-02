# Changelog

## 1.0.4 — 2026-10-02

**Hardening**

The base image's OS packages are upgraded at build. This node's scan was already
green; the panel's was not, on the same `python:3.12-slim` base, and a fix that
lands in one repo and not the other is how the two drift.

442 pass.

## 1.0.3 — 2026-10-02

The screen clears, and the output uses your terminal.

**Fixed**

- The screen never cleared: `command clear >/dev/null 2>&1` discarded the
  escape codes `clear` prints. Now `clear 2>/dev/null`, with the escape
  fallback kept for hosts without terminfo.
- The menu printed its prompt twice when the keystroke read timed out.
- The rule was a hardcoded 46 characters; it is now the terminal's width,
  clamped to [48, 100]. A pipe still gets 80.

Found by running the installer on a real pty, which is the only way to reach
these paths.

442 pass.

## 1.0.2 — 2026-10-02

**CI**

The workflow listed the lint targets as well as the Makefile did. It now calls
`make lint`, with `--output-format=github` moved into the Makefile rather than
dropped — losing it would have made CI quieter, not stricter.

442 pass.

## 1.0.1 — 2026-10-01

The panel's shape, and a data directory that matches the name.

**A bare install is interactive**

The installer read a missing terminal as "no questions wanted" and installed
anyway, reporting success for choices nobody made. A bare run is now interactive
unconditionally and stops without a terminal, naming `-y`. `update`, `uninstall`,
`recover-update` and `repair-unit` were never prompted and are unchanged. Bad
input is still reported as bad input.

**CLI**

- Bare `ovn` prints thirteen verbs and exits, like `ovm`. It used to open a
  numbered menu on a tty and die without one, so a provisioning script either
  hung or looked broken. The menu was also a second hand-maintained list of the
  tool's own commands.
- `ovn doctor` collects then renders: failures first, each fix in the label's
  column, passes counted, a clean run one line. `--all` works — it was in the
  help and did nothing.
- `credentials` is now `auth`; `restart-vpn` is now `restart core`.

**Fixed**

The node wrote its self-signed certificate to `/etc/ssl/self-signed` and
`chmod 600`'d the key. That is the panel's certificate directory on a shared
host, and 600 drops the group read the panel's service account needs. The node
now uses `/etc/ovnode/tls`. Two guards: the shared path appears nowhere in the
generator, and a session fixture fails the suite if it touches
`/etc/ssl/self-signed`, `/var/lib/ovnode`, `/etc/openvpn` or `/var/backups`.

Three commands shipped broken and every test passed, because the tests read the
source instead of running the command. Running every verb is now a test.

**Data directory**

`/var/lib/ovnode`, not `/var/lib/ovnode/<name>` — the nesting was a layout for
several nodes on a host that nothing implemented. `ovn update` migrates existing
installs before re-reading `.env`, copies rather than moves, and refuses to merge
rather than guessing which copy is live.

**Suite**

442 pass.

## 1.0.0 — 2026-09-29 — 2026-09-29

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
