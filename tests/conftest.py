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
from pathlib import Path

import pytest

TEST_OPENVPN_ROOT = Path(__file__).parent / ".test-openvpn"
TEST_OPENVPN_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("API_KEY", "test-api-key-1234567890")
os.environ.setdefault("OVNODE_OPENVPN_ROOT", str(TEST_OPENVPN_ROOT))
os.environ.setdefault("OVNODE_STATUS_FILE", str(TEST_OPENVPN_ROOT / "server" / "status.log"))


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
    import hashlib

    out = {}
    for raw in _REAL_PATHS_UNTOUCHED:
        path = Path(raw)
        if not path.exists():
            out[raw] = None
            continue
        digest = hashlib.sha256()
        for item in sorted(path.rglob("*")):
            if item.is_file():
                digest.update(str(item).encode())
                digest.update(item.read_bytes())
            else:
                digest.update(str(item).encode())
        out[raw] = digest.hexdigest()
    return out


@pytest.fixture(scope="session", autouse=True)
def _real_system_paths_untouched():
    """Fail the session if the suite wrote anything the host depends on."""
    before = _snapshot()
    yield
    after = _snapshot()
    changed = [p for p in before if before[p] != after[p]]
    assert not changed, (
        f"the test suite modified real system paths: {changed}. "
        "A test is writing outside its sandbox — see the note above."
    )
