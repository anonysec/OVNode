# Changelog

## 2.0.16 — 2026-11-13

- Management calls retry once after a short pause with a longer dial
  deadline when the single-slot OpenVPN management interface is briefly
  held (a status read or the other protocol's hook). A transient hold no
  longer turns a mobile reconnect into TAKEOVER → RESULT DOWN → REJECT.

## 2.0.15 — 2026-11-12

- Event push: `GET /sync/events` streams session changes, a display-only
  usage sample every 10 s and a 20 s heartbeat to the panel, fed by the
  client-connect/disconnect hooks over a local unixgram socket plus a 1 s
  state watcher. Steady-state node requests stay at zero while a stream is
  open; the panel falls back to polling on a 404 (pre-2.0.15 node).
- Hook sends are fire-and-forget (100 ms deadline): a missing or stalled
  agent cannot slow a VPN connect.

## 2.0.14 — 2026-11-12

- `/sync/usage` keyed `totals` and `totals_epochs` by the user DISPLAY NAME.
  The panel bills by parsing each key as a numeric panel id and drops anything
  else, so data usage never reached `users.used`. Key by common name.

## 2.0.13 — 2026-11-12

- A fresh install generated a constant API key (a 64-character placeholder
  committed in the source). Every node therefore shared one publicly known
  key. The installer now generates 32 random bytes with crypto/rand.

## 2.0.12 — 2026-11-12

- Ignore live rows that have no pool address. They are the connection being
  admitted or a rejected attempt, and counting them blocked the next login.

## 2.0.11 — 2026-11-12

- Exclude the connection being admitted from the live-session count. OpenVPN
  lists the new client before `client-connect`; a limit=1 user counted their
  own row as the old session and was rejected even with no other device.

## 2.0.10 — 2026-11-12

- The management auth budget is 2 seconds (it was 200 ms). A slow auth made
  the takeover send a kill with no reply, reject the reconnecting client, and
  leave the old session.
- The agent chmods the per-protocol status file to 0644 after OpenVPN starts,
  so the hook user can read it on a fresh install. (2.0.9's unit `UMask` did
  not cover the root-created status file.)

## 2.0.9 — 2026-11-12

- Takeover now uses the management `kill <cn>` command. `client-kill` by CID
  returns no reply under DCO and could leave the old session running; the
  verification also requires a complete `status 3` reply, so an empty reply
  cannot count as "verified".
- The systemd unit sets `UMask=0007`, so the per-protocol status files are
  group-readable by the runtime user the hooks run as. The status-file
  fallback can then count live sessions even when the management socket is
  unavailable.

## 2.0.8 — 2026-11-12

- The management `status 3` reply is tab-separated, but the hook parsed it as
  comma-separated. It therefore counted zero live sessions and let a
  max_logins=1 user open a second connection. Parse tabs (and commas for older
  status files), fall back to every protocol's status file when the management
  reply is empty, and recognize tab rows during takeover verification.

## 2.0.7 — 2026-11-12

- The uninstall confirmation now prints its question. It used to wait for
  input silently, so pressing Enter cancelled and the command looked broken.

## 2.0.6 — 2026-11-12

- `uninstall -y` (or `Yes=1`) now skips the final "remove the app and stop all
  services?" confirmation; it was unconditional, so an unattended uninstall
  always reported `cancelled`.

## 2.0.5 — 2026-11-12

- A custom-named CLI now passes its own `AppDir`, `Instance`, `DataDir`,
  `OpenVpnRoot` and `LogDir` (plus `Yes`/`Purge`) when it delegates to the
  installer, so `testnode uninstall` targets `/opt/testnode` instead of the
  default `/opt/ovnode` instance.

## 2.0.4 — 2026-11-12

- The bootstrap always downloads and checksum-verifies the requested release
  instead of reusing a leftover `AppDir/ovnode`. A stale copy could keep an
  older installer running, which made a renamed instance fall back to the
  existing `ovnode` tree.

## 2.0.3 — 2026-11-12

- A custom node name chosen in the wizard now gets its own shell files and
  CLI: the installer writes the embedded `install.sh`, `ovnode.sh` and
  `lib.sh` into that instance's tree, so `testnode` (for example) has
  `testnode status` and `testnode uninstall`. Previously only the binary,
  `.env` and the service were created for the new name.

## 2.0.2 — 2026-11-12

- The installer summary prints the instance's own certificate PEM (and only
  the PEM, not easy-rsa's OpenSSL text dump) plus its SHA-256 fingerprint.
  A second-instance install used to show the bootstrap node's certificate.

## 2.0.1 — 2026-11-12

- The installer is interactive on a terminal: node name, API port and key,
  VPN ports, protocol, TLS method, self-signed SANs, IPv6 and the panel
  allowlist. `-y` keeps the unattended defaults.
- Numbered install steps, with apt and easy-rsa output suppressed; apt uses
  `--no-install-recommends`, so the pcscd/opensc noise is gone.
- The self-signed server certificate takes its SANs from `TlsDomain`; the
  summary prints the certificate PEM and SHA-256 fingerprint for pinning.
- Includes the 2.0.0 fixes for dependency installation, resuming a partial
  first install, and running the binary downloaded in the current run.

## 2.0.0 — 2026-11-11

First release of the reset line. **No upgrade path from pre-2.0.0 builds**:
the database, state formats and config layout start here.

The node:

- Runs UDP, TCP, or both. `both` starts one OpenVPN process per protocol on
  the same port, with per-protocol config, status, PID, log and management
  socket. The instance owns a /23 (UDP: first /24, TCP: second) and NAT
  covers it once.
- Client profiles always use `<connection>` blocks, one per protocol and
  port, so a single `.ovpn` survives an ISP that blocks either transport.
- OpenVPN tuning is `state/openvpn.json`, managed from the panel: protocol,
  port, extra ports, max clients, keepalive, redirect, DNS, routes, IPv6,
  MTU/mssfix, cipher preference, TLS floor, renegotiation, idle timeout and
  verbosity. Server configuration and the template are generated from it;
  a failed apply rolls the file back.
- `.env` is twelve PascalCase keys with no product prefixes. Paths derive
  from `Instance`; nothing is shared between instances.
- One internal installer (the bash fallback is gone), typed exit codes, a
  bootstrap checksum gate, and `ovnode update` resolves `latest` itself.
- Per-instance host files: logrotate, cron, sysctl, NAT config, backups and
  the completion file all carry the instance name.
- Security: backup archives are framed and capped; the rate limiter sweeps
  on a timer instead of per request; both OpenVPN logs and the hook log are
  rotated; `LogLevel` is enforced.
- Removed the pre-2.0.0 state migration tree, unsigned usage counters, split
  policy files, the legacy `agent` path and `install-result.env`.

## 2.0.3 — 2026-11-11

The Go installer rewrite reaches a release: `install.sh` downloads the binary and `SHA256SUMS`, verifies the checksum, then runs `ovnode install`, with the previous bash installer kept as `install-legacy.sh`.

- `GET /sync/backup` serves the node PKI + state backup archive.
- The node negotiates wire-contract v3 with the panel.
- The pairing cache is invalidated when the panel lease expires.
- Rollback and restore validate the snapshot and every tar member before the agent is stopped; manifest keys, size and member count are capped.
- Bundle verify drains and closes gzip readers on every path, and caps the manifest.
- NAT extra ports are validated at load and clamped; `RUNTIME_USER`/`RUNTIME_GROUP` are validated when the environment file is written.
- PKI: EKU checked, secret permissions restored, systemd unit hardened; the agent supervises the OpenVPN child in a single unit.
- CI: staticcheck 2026.2.2, gosec v2.30.0, a deadcode gate, and a contract drift check against the panel.

## 2.0.2 — 2026-11-09

- Release binaries are verified against the release SHA256SUMS before install; the thin `install.sh` bootstrap downloads, verifies, then runs the Go installer (`ovnode install`). The previous bash installer ships one release as `install-legacy.sh`.
- Installer and docs fetch install.sh from `main` (latest).
- The start/installed menus are removed; `ovnode` prints the command list with no argument.

## 2.0.1 — 2026-11-04

Security:
- API key comparison hashes both sides; keys shorter than 16 characters are refused (HTTP 503).
- Rate limit: per-IP limit before auth, global limit after auth; an IP with 10 failed keys in 5 minutes is blocked with 429 before the key is compared.
- First boot prints a key fingerprint instead of the full API key.
- Pushed PEMs (PUT /sync/pki, PUT /sync/users/{cn}) are parsed, checked (CA flag, key match, chain, CN, expiry, 16 KiB cap) and re-encoded.
- PKI push takes the PKI lock and rolls back partial writes.
- Revoking a user now revokes every valid certificate of that name (a re-created user was previously left valid).
- CRL is refreshed daily; /sync/status reports crl_days_remaining and crl_matches_ca.
- Secret permissions: tls.key 0600, private dirs 0700, per-user dirs 0700; repaired on start and on restart; symlinks are never followed.
- Installer verifies the release binary against SHA256SUMS before install.
- Updater runs only a root-owned, non-writable install.sh with a minimal environment and a lock; POST /sync/update accepts an optional version (x.y.z); /sync/status shows update_status.

Behavior changes:
- POST /sync/config validates everything before writing, rolls back on failure, refuses reserved ports (22, API, management; extra ports also 80/443 unless allowed), and no longer reloads OpenVPN when nothing changed.
- CN rules: a CN must not start with a dot, and must equal its sanitized form.
- .env is no longer read from the current directory.
- NAT redirect rules carry the comment "ovnode-redirect" and are rebuilt on apply; redirects created by older versions are not removed automatically.

## 1.4.25 — 2026-11-04

- Security(pki): tls-crypt key chmod 0600 (was 0644); private dirs 0700; ca.key and *.key 0600; per-user dirs 0700. Added pki.EnsureSecretPerms() (serve start + update) and store.FixRuntimePermissions repair.
- Security(pki): atomic writes for serial, index, CRL, crlnumber, server cert/key (temp pair verified via tls.X509KeyPair before rename); RenewServerCert and nextSerial under lockPKI.
- Security(httpapi): handlePushPKI and CreateUserWithCredentials validate PEM (CA is CA, server cert chains to CA, key matches, CN matches, not expired, no trailing garbage, 16 KiB cap) and re-encode via pem.EncodeToMemory.
- Security(profile): BuildTemplate re-encodes pushed PEMs; store.WriteName rejects control characters.
- Fix(delete): DeleteUser removes all client material copies (issued/private/inline + user dir).


## 1.4.24 — 2026-11-01

- Fix(hooks): AgentBin points at the app binary (not data dir); server.conf stale hook lines are replaced on upgrade.

## 1.4.23 — 2026-11-01

- Remove doctor.sh: folded health checks out (doctor command dropped).

## 1.4.22 — 2026-11-01

- Fix(installer): restore OPENVPN_SERVICE default (fixes install_state_of tests).

## 1.4.21 — 2026-11-01

- Fix(vpn): default subnet changed to 10.66.0.0/24 to avoid stock OpenVPN's 10.8.0.0/24.

## 1.4.20 — 2026-11-01

- Feat(vpn): auto-derive unique 10.8.x.0/24 subnet per instance (no more collisions).

## 1.4.19 — 2026-11-01

- Feat(nat): port NAT helper to Go (`ovnode nat apply|cleanup`); drop /usr/local/sbin/ovnode-nat.sh.
- Feat(backup): daily DB backup moved into panel worker; drop ovmanager-backup unit.

## 1.4.18 — 2026-11-01

- Chore(services): drop NAT + cleanup systemd units (NAT applied in setup; purge via cron).

## 1.4.17 — 2026-11-01

- Fix(installer): create /var/lib/ovnode data dirs; write OVNODE_DATA_DIR to .env.

## 1.4.16 — 2026-11-01

- Refactor(paths): node data to /var/lib/ovnode, agent binary to /opt/ovnode/agent; Docker updated.

## 1.4.15 — 2026-11-01

- Fix(paths): rename agent binary to `agent` (no repeated ovnode in path).

## 1.4.14 — 2026-11-01

- Fix(installer): print `ovnode auth key` instead of removed `ovnode credentials`.

## 1.4.13 — 2026-11-01

- Feat(env): `.env` wins over process env (PasarGuard style) in fsx + mgmt/debug/log reads.
- Docs: note chunked sync/gRPC/stats as later/N-A.

## 1.4.11 — 2026-10-31

- Complete PasarGuard-style handoff suggestions 1-8.

## 1.4.10 — 2026-10-31

- Feat: print connection details on first successful serve.

## 1.4.9 — 2026-10-31

- Feat: write setup-info file (PasarGuard-style connection details).
- Feat: add `ovnode info` to print setup details.

## 1.4.8 — 2026-10-31

- Remove retired `ovnode credentials` alias; use `ovnode auth key`.

## 1.4.7 — 2026-10-31

- Fix(update): repair node_api_status version extraction.

## 1.4.6 — 2026-10-31

- Fix(update): make node_api_status return version and openvpn status so verification can pass.
- Fix(toolchain): use Go 1.27.3.
- Chore(security): triage gosec findings in probe/hooks.
- Test(credentials): add regression test.

## 1.4.5 — 2026-10-31

- Change(credentials): show the node certificate in `ovnode credentials`/`ovnode auth key`; remove standalone `ovnode certificate`.

## 1.4.4 — 2026-10-31

- Feat(installer): print node certificate content like the API key on the ready card.
- Feat(ovnode): add `ovnode certificate` (and `ovnode tls cert`) to print the panel-facing certificate.

## 1.4.3 — 2026-10-31

- Fix(httpapi): pass ResponseWriter to MaxBytesReader so oversized bodies return 413 instead of panicking.
- Fix(updater): reap detached update child to avoid zombies.
- Fix(pki): serialize RenewServerCertificateNative with the PKI lock.
- Fix(ovnode.sh): stop SIGHUP-ing unrelated OpenVPN processes.
- Fix(install.sh): keep install.sh/compose in Docker build context.

## 1.4.2 — 2026-10-31

- Fix(pairing): fail closed on unreadable or corrupt pairing state instead of resetting ownership.
- Fix(ovpn): serialize `ChangeConfig` to prevent concurrent server.conf/client-common.txt races.
- Fix(store): invalidate usage cache after `BankUsage` writes.
- Fix(version): complete version bump to 1.4.2 across all version spots.
- Fix(docker): stop excluding `install.sh` and `scripts/compose/` from Docker build context.
- Security(telemetry): retry CSPRNG reads in `newEventKey` until success.
- Chore(pki): remove unused unsafe `fillRand` helper.

## 1.4.0 — 2026-10-31

- Fix(installer): a fresh server no longer reports "already installed" (exit 3)
  and install nothing. `main` called `load_helpers` — which downloads the
  release binary *into* `APP_DIR` — before the `[[ -d $APP_DIR ]]` check, so the
  bootstrap's own `mkdir` answered the question. The installation state is now
  read once, before the bootstrap, and every later check reads it.
- Fix(installer): an installation is now recognised by what a node owns —
  `.env`, the verified binary, its systemd units, its data directory — instead
  of by the existence of `APP_DIR`, which the bootstrap creates. A directory
  left by an interrupted bootstrap is reported and installed over, and nothing
  in it is deleted; an installed node is still never overwritten or removed,
  and the remains of a node (unit files, or data with no app) are refused rather
  than adopted with a second identity.
- Fix(installer): `update`, `uninstall`, `recover-update` and `repair-unit` on a
  box with no node exit 4 before downloading anything, instead of writing a
  binary into `APP_DIR` and then reporting "not installed". `uninstall` still
  handles the remains of a node, unpacking its helpers in a scratch directory
  rather than into `APP_DIR`.
- Test: `scripts/test-installer.sh` (also `make check-installer`, run in CI)
  covers fresh and existing installs, interactive, wizard and `-y`, leftover
  bootstrap directories, node remains and `--local`, with a local release
  fixture instead of the network.

- Fix(pki): generate standard OpenVPN static key at `/etc/openvpn/server/tls.key` for tls-crypt.
- Fix(restore): preserve executable permissions on restored agent scripts and binaries.
- Fix(cli): eliminate legacy `ovn` command in favor of `ovnode`.
- Chore: removed `ovnode://` registration bundle URI from installer and CLI outputs.
- Test: updated HTTP API contract test table to recognize `/sync/user` creation and reset routes.

## 1.3.0 — 2026-10-07

Single-panel pairing: X-Panel-ID lease enforced in check_api_key (all keyed
routes). First panel pairs; foreign panels get 409 while the 30-minute lease
holds, silent takeover after expiry; anonymous (headerless) requests pass only
while unpaired. New CLI: `ovnode auth disconnect` clears pairing immediately.
Unkeyed /sync/health unaffected.

Panel-owned PKI: node accepts pushed credentials. New endpoints PUT /sync/users/{cn}
(pushes cert + key + state) and PUT /sync/pki (pushes CA + server cert + server key).
create_user_on_server writes request PEMs (no local easy-rsa fork); legacy local
generation kept as documented fallback. OpenVPN reload via management socket (no
systemctl). Cert validation on connect now trusts the panel-pushed CA.

## 1.0.48 — 2026-10-06

Hot-path forks removed from the max-login hook: `sanitize()` uses a bash
builtin instead of forking `sed`, and `log()` appends to
`/var/log/ovnode/hook-events.log` instead of forking `logger` (rotation is
handled by a new `/etc/logrotate.d/ovnode` stanza). The allow path now forks
only `flock`, `awk` and `mkdir -p` for the log directory.

The hook also fails closed on a malformed identity: an empty CN after
sanitize, a CN longer than 64 characters, or one that does not match
`[A-Za-z0-9_.][A-Za-z0-9_.-]*` is rejected. This is a deliberate hardening —
the empty-CN path previously allowed the connection.

OpenVPN now runs under a dedicated `ovnode-openvpn.service` unit instead of
the distro's `openvpn-server@server`, so install, restart, log rotation and
repair no longer touch the system unit. Docker mode still stops
`openvpn-server@server` when it conflicts on the shared host network.

Stale session markers are purged daily by `ovnode-cleanup.timer` running
`backend/scripts/cleanup_stale_sessions.py`: a marker older than 24h whose
pool IP is absent from the live status file is removed. The purge touches only
`sessions/*`; user config (`limit`, `disabled`, `state`, `.ovpn`) is never
modified.

## 1.0.47 — 2026-10-06

Structural harmonization with OVManager. The agent's code directory is renamed
`core/` → `backend/`, matching the panel's layout, with every import and path
reference updated (Python, shell, Dockerfile, CI, docs). Docker assets move
under `scripts/compose/`: the reference `docker-compose.yml` and
`docker/entrypoint.sh` now live there, and the image copies the entrypoint from
its new location.

Root docs are standardized: the duplicate `CONTRIBUTING.md` and
`CODE_OF_CONDUCT.md` are removed in favour of `.github/CONTRIBUTING.md` and a
Contributor Covenant `.github/CODE_OF_CONDUCT.md`; `NOTICE`, `roadmap.md` and a
`.github/pull_request_template.md` are added. AI/tooling files (`.opencode/`,
`AGENTS.md`, `docs/superpowers/`) are gitignored and the local brainstorming
artifacts removed from the working tree.

## 1.0.46 — 2026-10-05

Multi-login policy simplified: the allow/reject decision uses only the live
OpenVPN status count, dropping the reconnect-absorption and stale-cleanup
loops. A new kill-reason sidecar lets the panel toast a user displaced by a
limit=1 takeover.

## 1.0.45 — 2026-10-05

Housekeeping: restore `.claude` to `.dockerignore` (OVManager kept
it as belt-and-suspenders) and ignore `docs/` in `.gitignore` so
the untracked superpowers plan artifact from the reverted refactor
is not staged by mistake.
## 1.0.45 — 2026-10-04

The installer's menu takes numbers, and waits for nobody.

**Changed**

The front door is one numbered menu — install, install with docker, and, on a
host that already has OVNode, uninstall and update. Installing over an existing
install updates it rather than starting over, keeping the database, the URL
path, the certificate and the owner's credential; declining prints the command
that reinstalls from scratch.

The menu reads a number instead of arrow keys. The arrow-key version redrew the
menu in place and read single keystrokes from `/dev/tty` with a timeout, so a
pasted line, a closed terminal or a tmux that lost the pane could leave a
half-drawn frame — and every one of those timeouts was a branch to get right.
The panel's installer moved the same way in the same release, which keeps the
two installs describing themselves in the same words.

## 1.0.43 — 2026-10-03

**Tests**

The renderer parity check reads the panel's code rather than its bytes.

The panel inlined its helper block into `install.sh`, so
`scripts/lib/render.sh` no longer exists there and this test died on
`FileNotFoundError` instead of on the drift it exists to catch. It now reads
the render section out of the panel's `install.sh` and compares code —
comments and blanks excluded. The node's helpers still live in
`scripts/lib/render.sh` and the panel's are inline, so the comment above each
block is a true statement on its own side; requiring those to match would fail
on the very difference the assertion exists to ignore. Everything that executes
is still required to be identical.

**Changed**

`scripts/lib/` stays here. The panel's equivalent helpers moved inline into its
own two programs, so the two repos no longer share a file layout — only the
renderer's behaviour, which is what the parity test pins.

442 pass, 1 skipped.

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

- Bare `ovnode` prints thirteen verbs and exits, like `ovmanager`. It used to open a
  numbered menu on a tty and die without one, so a provisioning script either
  hung or looked broken. The menu was also a second hand-maintained list of the
  tool's own commands.
- `ovnode doctor` collects then renders: failures first, each fix in the label's
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
several nodes on a host that nothing implemented. `ovnode update` migrates existing
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
key. The install ends with the node name and API key for
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

- `ovnode credentials` reprints the node name and API key at any
  time; the install summary is no longer the only place they exist.
- `ovnode restore` lists data backups and restores one, taking a safety copy first.
- `ovnode update` snapshots identity, node data, `/etc/openvpn` and the API TLS
  files before it starts, and rolls back if the new release does not come up.
- `ovnode completion` installs shell completion.
- `install.sh version-script` reports which installer was actually run.
- Read-only commands report an unreadable `.env` as an error instead of
  reporting defaults that look like real data.
- `uninstall` keeps data unless `--purge`, and its confirmation defaults to No.
