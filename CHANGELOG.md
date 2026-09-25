# Changelog

## 1.0.1 — 2026-09-25

Everything merged after the v1.0.0 tag, validated live. The release
tarball is the first one that actually contains it:

- Installer/CLI parity with the panel flow, focused status, clear menus.
- Generated client `.ovpn` never carries `UPDATE_VIA_PANEL`; falls back
  to the node's own public address.
- Connection rejects are classified (policy vs real failure); only
  failures raise the auth-error counter. The strict max-login line
  counts as policy. TLS/auth failures are scanned from the OpenVPN log
  and timed by first/last-seen observation (no log-timestamp directive:
  OpenVPN 2.7 rejects it and refuses to start).
- Every generated server.conf directive is checked against the
  installed OpenVPN's option list, so an invalid directive fails a test
  instead of the node.

Pairs with OVManager 1.0.2.

## 1.0.0 — unreleased

Version reset: pre-publish cleanup. History was rewritten to a single identity, all prior releases/tags removed, numbering restarted at 1.0.0. Node redesign continues on `dev` before the first public release.

## 1.1.6 — 2026-09-21

Redesign release (squash of #5): transactional reboot-safe updates with
persisted journals and `ovn recover-update`, manifest-linked state safety
snapshots, Docker installs from the published versioned image (no local
builds), beginner-first installer (Install / Install with Docker, host
default), maintenance guard blocking mutating API calls during
verification, extended doctor (update transactions, snapshots, VPN PKI,
unit, locks) with safe `--fix`, `repair-unit`, and a documented
panel/node version compatibility policy. Validated live against panel
1.2.8. Pairs with OVManager 1.2.8.

## 1.1.5 — 2026-09-20

Checksum-mismatch follow-up (mirror of panel 1.2.7): archive check
before the checksum with a re-bootstrap hint, Pages bootstrap URL
retired for raw.githubusercontent.com, stepped installer menus
(Step N/4) with shorter copy.

## 1.1.4 — 2026-09-20

Follow-up fixes: release downloads follow redirects (`curl -L`),
entry-point executable bits pinned by tests. Pages auto-deploy off.

## 1.1.3 — 2026-09-20

Critical fixes over 1.1.2: `doctor`/`rollback` were rejected by `parse_args`
(the main branches existed but the parser didn't know the words), and
rollback now checks the install dir before requiring root (CI-safe).

## 1.1.2 — 2026-09-20

Fresh rewrite of the shell layer (Concept A): tiny installer with
zero-question defaults, numbered `interactive` wizard, `--version` pins,
code snapshots with automatic update rollback, and plan output by default.
New `ovn doctor` (agent, VPN, disk, cert, backups) with `--fix`, and
`ovn rollback`. Flags cut to `-y/-j/-h/-p/--purge`; `--key` replaces
`--api-key` (`OVN_KEY`); `--tls` takes 1-4 (names still accepted).

## 1.1.1 — 2026-09-19

Concept-A split: the installer (`install.sh`) only installs, updates and
uninstalls; day-to-day operations move to the manager (`manager.sh`,
installed as `ovnode`/`ovn`) with a numbered menu. Shared shell code lives
in `lib/common.sh`. Updating auto-swaps the old installer-copy CLI for the
manager. `--tls` takes numbers 1-4 (names still accepted); `status`/`logs`/
`backup`/`tls` on `install.sh` now redirect to `ovn`. Also fixed: the TLS
menu called an undefined `kv`, and `spinner` could end with a failing test
under `set -e`.

## 1.1.0 — 2026-09-19

Version reset: the `2.x` release line is retired and the project continues
on the `1.x` line. No code changes in this release — version strings only.
Pairs with OVManager panel `1.2.2` (same sync API contract).

- `pyproject.toml`, `core/version.py`, `install.sh` and the README badge now
  report `1.1.0`.
- All `2.x` GitHub releases, tags and container images are removed.

## 1.6.0

- Pre-freeze state: ECDSA PKI, dynamic-IP-safe sessions, multi-port,
  per-user store, envelope sync API.
