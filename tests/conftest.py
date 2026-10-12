# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Portable test defaults; production paths remain unchanged."""

# anyio 4.15 moved BlockingPortal to anyio.from_thread and emits a
# DeprecationWarning on the old anyio.abc alias — which starlette's
# TestClient still reads at import (annotations evaluated eagerly). Both
# packages are at latest; pre-binding the new location keeps the suite
# warning-free until starlette catches up.
import anyio.abc
import anyio.from_thread

if "BlockingPortal" not in anyio.abc.__dict__:
    anyio.abc.BlockingPortal = anyio.from_thread.BlockingPortal  # type: ignore[attr-defined]

import os
import pty
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

TEST_OPENVPN_ROOT = Path(__file__).parent / ".test-openvpn"
TEST_OPENVPN_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("API_KEY", "test-api-key-1234567890")
os.environ.setdefault("OVNODE_OPENVPN_ROOT", str(TEST_OPENVPN_ROOT))
os.environ.setdefault("OVNODE_STATUS_FILE", str(TEST_OPENVPN_ROOT / "server" / "status.log"))
# The max-login hook appends to a file now (no syslog fork); keep those writes
# inside the sandbox instead of the real /var/log/ovnode.
os.environ.setdefault("OVNODE_LOG_DIR", str(TEST_OPENVPN_ROOT / "logs"))


# ── The suite must not write to the real system ──────────────────────────
#
# The panel repo has had `_system_paths_untouched` for a while. The node did
# not, and the gap was found the hard way: a sweep that ran `ovn tls
# selfsigned` reached generate_selfsigned, which wrote /etc/ssl/self-signed
# — OVManager's panel certificate on a shared host — and chmod 600'd the key.
# The panel then failed to start and sat in a systemd restart loop, reporting a
# certificate error that named neither project.
#
# So the guard is here rather than in one test: snapshot the paths a test must
# never touch, and fail the session if any of them changed. That catches the
# class rather than the instance, including whatever reaches them next.

_REAL_PATHS_UNTOUCHED = (
    "/etc/ssl/self-signed",
    "/etc/ovnode",
    "/var/lib/ovnode",
    "/etc/openvpn",
    "/var/backups",
)


def _snapshot() -> dict:
    """Name, size and mtime of everything under each path.

    Deliberately not a content hash. `/var/backups` holds 59MB of tarballs, and
    hashing every byte of it twice per session is both slow and a source of
    flakes: a file being written by something else — including an OVManager
    update on the same host — changes under the read, which is indistinguishable
    from the suite having written it. Size and mtime catch the case that matters
    (a test created, truncated or removed something) without either cost.
    """
    import hashlib

    out = {}
    for raw in _REAL_PATHS_UNTOUCHED:
        path = Path(raw)
        try:
            if not path.exists():
                out[raw] = None
                continue
            digest = hashlib.sha256()
            for item in sorted(path.rglob("*")):
                try:
                    stat = item.stat()
                    digest.update(f"{item}:{stat.st_size}:{stat.st_mtime_ns}".encode())
                except OSError:
                    # Vanished or unreadable between the walk and the stat. A
                    # guard that raises here would fail the suite for something
                    # it cannot attribute, which is worse than missing it.
                    digest.update(f"{item}:unreadable".encode())
            out[raw] = digest.hexdigest()
        except OSError as exc:
            out[raw] = f"unreadable: {exc}"
    return out


# The guard belongs to the controller process, not to a session fixture: an
# xdist worker runs its own "session", so a per-worker window both misses
# writes made before a late worker starts and multiplies one host event into
# N worker errors (observed: 2 errors under -n auto). PYTEST_XDIST_WORKER is
# set by xdist before conftest loads, so the worker check cannot race hook
# registration. One window around the whole run, one verdict.


def pytest_configure(config):
    """Snapshot the guarded paths before the first test of the run."""
    if os.environ.get("PYTEST_XDIST_WORKER"):
        return
    config._ovnode_paths_before = _snapshot()


def pytest_sessionfinish(session, exitstatus):
    """Fail the run if anything under the guarded paths changed."""
    if os.environ.get("PYTEST_XDIST_WORKER"):
        return
    before = getattr(session.config, "_ovnode_paths_before", None)
    if before is None:
        return
    after = _snapshot()
    changed = [p for p in before if before[p] != after[p]]
    if not changed:
        return
    # Straight to stderr: the run's summary has not printed yet at this
    # point, and a terminalreporter.section() write made here is swallowed
    # while the same sys.stderr line is not.
    print(
        f"the test suite modified real system paths: {changed}. "
        "A test is writing outside its sandbox — see the note above.",
        file=sys.stderr,
    )
    # pytest-cov's pattern: the value main() returns is read after the
    # sessionfinish hooks, so this is what turns the verdict into exit 1.
    session.exitstatus = 1


# ── Shared bash harness, cached by input ────────────────────────────────
#
# The transcript suites fork bash per probe, and the same probe repeats
# across tests — one golden script asserted from several angles. Memoizing
# by exact input gives one fork per unique probe and byte-identical results
# on every hit; each probe is a hermetic process with a fixed env, so the
# first run's bytes are the only bytes there are.
# ponytail: in-memory per worker — xdist workers never share the cache.


class BashHarness:
    """Probe renderer.sh and run manager.sh, caching by exact input."""

    def __init__(self, lib: Path, manager: Path):
        self._lib = lib
        self._manager = manager
        self._cache: dict[tuple, object] = {}

    def probe(self, script: str, *, promptable: bool) -> str:
        """A bash file with the libs sourced and one snippet appended."""
        return (
            "set -Eeuo pipefail\n"
            f'. "{self._lib / "common.sh"}"\n'
            f'. "{self._lib / "render.sh"}"\n'
            f"can_prompt() {{ return {0 if promptable else 1}; }}\n"
            f"{script}\n"
        )

    def run(self, script: str, *, tty: bool, **env: str) -> str:
        """Run a snippet WITHOUT a terminal and return raw stderr.

        The pipe path: no -t 2, so no colour and no animation. Pass tty=False
        for it — the flag is kept only so the intent reads at the call site,
        because a test that thinks it has a terminal but does not is exactly
        how the fade tests came to assert nothing.
        """
        assert not tty, "use run_pty for anything that needs a real terminal"
        key = ("pipe", script, tuple(sorted(env.items())))
        if key not in self._cache:
            full = self.probe(script, promptable=False)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "probe.sh"
                path.write_text(full, encoding="utf-8")
                r = subprocess.run(
                    ["bash", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env={**os.environ, **env},
                    stdin=subprocess.DEVNULL,
                )
            assert r.returncode == 0, r.stderr
            self._cache[key] = r.stderr
        return self._cache[key]  # type: ignore[return-value]

    def run_pty(self, script: str, *, stdin_pipe: bool = False, **env: str) -> str:
        """Run a snippet WITH a terminal on stderr, and return what it drew.

        A pty is the only way to get -t 2 true, and -t 2 is what gates colour,
        animation and the whole repaint path. Without this the fade, the spinner
        and the cursor accounting are untested code that only runs on a
        developer's terminal.

        stdin_pipe=True models `curl … | bash`: stdin is a pipe, stderr is still
        the operator's terminal.
        """
        key = ("pty", script, stdin_pipe, tuple(sorted(env.items())))
        if key not in self._cache:
            full = self.probe(script, promptable=True)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "probe.sh"
                path.write_text(full, encoding="utf-8")
                master, slave = pty.openpty()
                proc = subprocess.Popen(
                    ["bash", str(path)],
                    stdin=subprocess.PIPE if stdin_pipe else subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=slave,
                    # TERM is set here rather than inherited. render.sh gates motion
                    # on ${TERM:-dumb}, so a runner with no TERM — which is what
                    # GitHub's non-interactive steps are — gets every test below
                    # passing on a developer terminal and failing in CI, with the
                    # message "no repaint happened at all" for a repaint that was
                    # never going to be attempted. These tests are about what a
                    # terminal draws, so they ask for a terminal.
                    env={"TERM": "xterm-256color", **os.environ, **env},
                )
                os.close(slave)
                chunks = []
                try:
                    while True:
                        try:
                            data = os.read(master, 65536)
                        except OSError:
                            break
                        if not data:
                            break
                        chunks.append(data)
                finally:
                    os.close(master)
                    proc.wait(timeout=60)
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            raw = b"".join(chunks).decode("utf-8", "replace")
            assert proc.returncode == 0, raw
            self._cache[key] = raw
        return self._cache[key]  # type: ignore[return-value]

    def manager(self, *args: str, check: bool = True) -> str:
        """Run manager.sh with the suite's fixed env; return stdout + stderr."""
        key = ("manager", args)
        if key not in self._cache:
            out = subprocess.run(
                ["bash", str(self._manager), *args],
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "OVN_APP_DIR": "/nonexistent", "CI": "1"},
            )
            self._cache[key] = (out.returncode, out.stdout + out.stderr)
        rc, combined = self._cache[key]  # type: ignore[misc]
        if check:
            assert rc == 0, combined
        return combined  # type: ignore[return-value]


_REPO = Path(__file__).resolve().parent.parent
HARNESS = BashHarness(_REPO / "scripts" / "lib", _REPO / "manager.sh")


@pytest.fixture(scope="session")
def harness() -> BashHarness:
    return HARNESS
