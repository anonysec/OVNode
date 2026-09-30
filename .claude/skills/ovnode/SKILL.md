---
name: ovnode
description: Use when working in the OVNode repository — the OpenVPN node agent that runs as root. Verify commands, system dependencies, layout of install.sh / manager.sh / scripts/lib, house rules, release flow, and the shell, PKI and credential traps this codebase has actually hit.
---

# OVNode (node agent)

The node half of the OVManager/OVNode pair. Panel: `/root/workspace/OVManager`.
Shared project instructions live in `/root/workspace/CLAUDE.md`; the `ovmanager-dev`
and `ov-release` skills go deeper — this file is the repo-anchored version.

This agent runs as **root** and drives OpenVPN, so a change here can take a
customer's VPN down. The bar reflects that.

## Verify before claiming done

```bash
.venv/bin/python -m pytest tests/ -q
.venv/bin/ruff check core tests
.venv/bin/ruff format --check core tests
bash -n install.sh manager.sh scripts/lib/*.sh
```

`make test` / `make lint` / `make verify` wrap these (`verify` = `lint` plus the two
import smoke checks). CI (`.github/workflows/ci.yml`) runs the same suite, and lint
runs under `--output-format=github`.

The suite needs `openvpn`, `easy-rsa`, `iptables`, `iproute2` and `logrotate` present
— `tests/test_openvpn_pipeline.py` drives easy-rsa and the openvpn binary for real
rather than stubbing them, so a missing package shows up as a late failure, not a skip.

**Tests that need root are gated, not deleted.** CI runs unprivileged and this machine
runs as root, so anything asserting ownership or an unreadable file uses `skipif` on the
effective uid. Gate new ones the same way — a test that passes as root and fails in CI
is worse than no test.

## Where things live

| Path | What |
|---|---|
| `install.sh` | installer, updater and uninstaller. Three flags (`-y`, `--docker`, `-h`); everything else is an `OVN_*` variable. Older spellings still work but warn. |
| `manager.sh` | the `ovnode` CLI, installed as `ovn`. Install/update/uninstall delegate to `install.sh` so there is one copy. |
| `scripts/lib/common.sh` | output, prompts, `env_get`/`env_set`, TLS and menu helpers. `install.sh` declares `LIB_FILES=(common.sh)` and sources it; `manager.sh` sources it too. |
| `core/` | FastAPI app, OpenVPN orchestration, easy-rsa PKI. |
| `core/openvpn/pki/paths.py` | every path the PKI writes to, in one leaf module. |
| `docker-compose.yml`, `Dockerfile` | the `--docker` install mode. |
| `tests/test_version_parity.py` | pins every place the version is written. |

Default install layout: app in `/opt/ovnode`, state in `/var/lib/ovnode`, PKI under
`/etc/openvpn/server/`, service `ovnode.service`, port 2083.

## House rules

Full list in `/root/workspace/CLAUDE.md` and `.github/CONTRIBUTING.md`. The ones a
change actually trips over:

- **`scripts/lib/*.sh` is the only definition of a shared shell helper.** `install.sh`
  and `manager.sh` source it; never copy a function into either.
- **A read-only command that cannot read `.env` must say so.** Never fall back to a
  default that looks like data — plausible values you failed to read are worse than an
  error. `env_get` in `scripts/lib/common.sh` dies rather than return empty.
- **Never print a private key or a full config.** Key material stays `0600`; the backup
  helper sets `umask 077` before tarring the PKI.
- Treat every request-supplied path as hostile: resolve it and confirm it stays inside
  the intended root before any read, write, or delete.
- Comments must earn their place — explain a non-obvious tradeoff or a bug that was
  actually hit, not what the code says.

## Traps this codebase has hit

### `${BASH_SOURCE[0]}` is unbound under `set -u` when the script arrives on stdin

The documented pipe form (`cat install.sh | bash -s --`) leaves it unset, and `set -u`
turns that into "unbound variable" before setup runs. Always spell it
`"${BASH_SOURCE[0]:-}"`. Explained at `install.sh:117`; the guard is `install.sh:121`.
`manager.sh:52` uses the bare form because it is never piped.

### A function whose last statement is `[[ … ]] && cmd` returns 1

Under `set -Eeuo pipefail` (both entrypoints) that aborts the caller. The
`[[ "$YES" -eq 1 ]] && return 0` lines in `scripts/lib/common.sh` are early returns
inside a longer function, which is fine — the trap is when nothing follows. Use `if`
and end with an explicit `return`.

### One definition per shell function

`tests/test_no_duplicate_functions.py` asserts that no function is defined in two
files, with `main`, `parse_args` and `show_help` exempted as per-script entry points.
A new shared helper belongs in `scripts/lib/`, never inlined.

### The PKI is not source

`paths.py` roots at `OVNODE_OPENVPN_ROOT` (`/etc/openvpn` by default): CA and issued
certs in `server/pki`, `server/tls.key`, `server.conf`, and `server/mgmt-pass` (the
management password, `0600` — localhost is shared in host-network mode, so the socket
must authenticate, not merely bind). `.claude/settings.json` denies reads of these;
keep it that way.

## Releasing

`ov-release` covers the whole checklist. The two things worth repeating:

- The node has five version spots: `pyproject.toml`, `core/version.py`, `install.sh`,
  `manager.sh`, and the README badge, plus a new `CHANGELOG.md` heading.
  `tests/test_version_parity.py` asserts them, but the list is enumerated, not
  discovered.
- Publish the GitHub release **before** the runtime smoke. `install.sh` downloads the
  release tarball, not the source tree, so an install between push and release fails.
  GitHub Pages is not enabled for this repo (a 404 there is expected).

This machine is the test VPS: the node installs to `/opt/ovnode` on port 2083 as
`ovnode.service`. Clean up with `install.sh uninstall --purge -y` afterwards, and when
the panel is installed on the same host the order is panel first, then node, then
`systemctl restart ovmanager`.
