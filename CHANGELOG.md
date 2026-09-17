# Changelog

## 2.1.2 — 2026-09-17

Companion to panel 2.1.2.

- Uninstall/update stop and restart every unit through a 20-second bound and
  force-kill on timeout, so a stuck service can no longer freeze the
  installer; units that are not loaded are skipped quietly.
## 2.1.1 — 2026-09-17

Companion to panel 2.1.1. No node-agent behavior changes.

- Installer: passwords echo as `*` while typing; uninstall asks
  "Also delete data and backups?" (default No); default node name is
  `ovnode`.
- Backups: `backup --keep N` prunes old `/var/backups` tarballs, and a host
  timer can run it daily via `ovnode auto-backup on|off|status
  [--time HH:MM] [--keep N]` (off by default).

## 2.1.0 — 2026-09-17

Companion release to OVManager panel 2.1.0 — same sync API contract.

**Highlights**

- **Security/reliability** (Step 1): 0600 `.ovpn` profiles written
  atomically, CRL regenerated on retried deletes, IP-keyed API rate
  limiting, non-ASCII key safety, no plain HTTP on new installs, installer
  backups root-only + `mktemp` downloads.
- **Installer** (Step 2): Express/Custom/Update/Uninstall menu, TLS
  self-signed default, and the `ovnode` / `ovn` terminal menu (status,
  service, restart VPN, logs, backup, update, TLS).
- **Panel-managed settings** (Step 3): DNS servers, IPv6 on/off, extra VPN
  ports and a restart action driven from the panel; `POST /sync/update`
  for node self-update.
- **Scale**: bounded fan-outs on the panel side; the node stays one small
  FastAPI process with file-based state.

**Step 1 — reliability/security batch**

- `client.ovpn` files (they embed the client private key and tls-crypt PSK)
  are created 0600 via temp-file + atomic replace and removed on failure;
  downloads never serve a partial/corrupt profile.
- A retried delete regenerates the CRL when it is older than the PKI index,
  so a revoked certificate can never stay accepted.
- API rate limiting is keyed by client address (not the attacker-supplied
  key) with a global ceiling; non-ASCII keys get 401 instead of 500; the
  lazy certificate path on downloads charges the heavy bucket.
- `PUT /sync/user` without `max_logins` leaves the stored limit alone.
- PKI initialization is serialized with its own lock; `server.conf` and the
  client template stay 0644 so SIGHUP reloads work after privilege drop.
- Usage resets take the connect/disconnect hook's `flock`; empty management
  password files no longer raise; enforcement hooks install atomically.
- `/redoc` and `/openapi.json` are hidden together with `/doc`.
- Installer: root-only PKI backups (`umask 077`), `mktemp` downloads instead
  of a fixed `/tmp` path, 0600 self-signed key.

- Installers (Step 2): bare interactive runs open a menu —
  Express / Custom / Update / Uninstall. Express asks nothing: `node-1`,
  UDP, self-signed TLS, generated API key. Custom keeps the full wizard.
- TLS is always on: self-signed is the default (and the unattended default);
  plain HTTP (`--tls none`) is rejected with a clear usage error. The panel
  can still switch an existing node's TLS mode.
- Fixed a bug where a bare interactive install died asking for an API key
  before the wizard could generate one; UDP is now the default transport.

- Panel-managed DNS: `POST /sync/config` accepts optional `dns1`/`dns2`,
  rewrites the pushed DNS lines in server.conf (no duplicates) and SIGHUPs.
- Node software update: `POST /sync/update` (heavy rate bucket) runs the
  installer's own `update --json` detached on native installs; Docker answers
  with host-side guidance instead of pretending to update.
- VPN service control: `POST /sync/restart` reloads/restarts OpenVPN and
  reports whether it came back.
- Runtime IPv6 toggle from the panel: `POST /sync/config` accepts optional
  `enable_ipv6` / `ipv6_prefix`, rewrites the IPv6 block in server.conf
  without duplicates and SIGHUPs (no full restart).
- Panel-managed extra VPN ports: `POST /sync/config` accepts optional
  `extra_ports`; the client template is rebuilt with one `remote` per port
  (cached profiles invalidated) and native installs re-apply NAT via
  `ovnode-nat.sh` (Docker notes that NAT comes from the container env).
- Terminal menu (TUI): installs `ovnode` (+ `ovn` alias) to
  /usr/local/bin — Status, Start/Stop/Restart agent, Restart VPN, Logs,
  Backup, Update, TLS and Uninstall, with boxed `whiptail` dialogs when
  present and the colored menu otherwise. Every item is also a subcommand
  for scripts (`logs -f`, `restart-vpn`, stable exit codes).
- Installed machines now open the TUI directly on a bare run (the fresh
  install menu no longer appears first).

**Gap-closure pass**

- Certificate work no longer freezes the agent: create/delete/download run
  in the threadpool, so `/sync/health` and the panel stay responsive while
  easyrsa works (up to minutes on delete).
- A config push whose OpenVPN restart fails now **rolls back**
  `server.conf` (and the client template when changed) from the `.bak`
  copies and retries the restart, reporting failure instead of silently
  leaving a broken config. When no `.bak` exists the new config stays and
  activates on the next start.
- Added `docs/how-it-works.md` (plain-words architecture).
- `POST /sync/renew-cert` renews the OpenVPN server certificate with
  easyrsa (old cert archived), restarts OpenVPN and returns the new expiry
  date; rate-limited like other certificate operations.

## 2.0.2 — 2026-09-07

Pairs with OVManager panel `2.x`.

- Reconnect: dynamic-IP `max_logins=1` takeovers verified via mgmt-live
  check, kill all CIDs for the CN, status-aware grace, per-(CN,pool) dead
  cleanup; keepalive 10 60 fresh-only.
- Restart policy: no-op push = zero daemon restarts, tunnel-only = no
  signal, proto/port = one restart, normalization = SIGHUP; entrypoint
  watches content hash + dual-proto NAT with stale prune.
- Hook perf: one python mgmt session per takeover, builtin marker parsing,
  single status prefilter, EPOCHSECONDS, per-CN locks.
- Low-end: users/<cn>/{limit,disabled} merged into one 0644 `state` file
  (dual-read fallback, writer converges, `.lock` cleanup); status
  mtime+size parse cache shared by all endpoints; fresh verb 2, P-256.
- Obs: hook ip/pool on decisions, client IP on 401/429; usage-reset
  endpoint; `ca_expiry`/`server_expiry` in status.
- Fresh defaults: no legacy ciphers, mssfix/buffers, no-compression,
  block-outside-dns, TLS 1.3, ipp flush, max-clients 250, fast-io on UDP.
- Installer: `--proto`/`OVN_PROTO` prompt, docker liveness check,
  native-HUP logrotate, evict native openvpn daemon on docker
  install/update, env recovery survives missing `.env` keys.

## 2.0.1 — 2026-09-05

- P1 batch: single `server.conf` writer, easyrsa lock, usage-reset
  endpoint, `ca_expiry`/`server_expiry` in status, firewall cleanup.
- Installer test hermetic on installed machines (`OVN_APP_DIR`).
- Docs: badges, compat matrix, `OVN_REPO` fork override.

## 2.0.0 — 2026-09-05

Pairs with OVManager panel `2.x`.

- License: MIT (was proprietary).
- Fix: connect hook answers the management password challenge, so
  `max_logins=1` takeover kills work on hardened installs.
- Docker: supervisor restarts OpenVPN fully when `server.conf` changes
  (SIGHUP cannot rebind port/proto); NAT re-applied on restart.
- New: `GET /sync/config` reports live port/proto/tunnel (drift detect).
- Perf: API-TLS cert expiry cached 5 min (was an `openssl` fork per poll).
- Lint gate clean (`ruff format --check`).
- Headers: SPDX-MIT across the tree.

## 1.6.0

- Pre-freeze state: ECDSA PKI, dynamic-IP-safe sessions, multi-port,
  per-user store, envelope sync API.
