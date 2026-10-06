# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Stale session marker purge (``cleanup_stale_sessions.py``).

Only markers older than the TTL whose pool IP is absent from the live status
file are removed; fresh markers and markers whose pool IP is still live stay.
"""

import json
import os
import subprocess
import sys
import time

SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "backend", "scripts", "cleanup_stale_sessions.py"
)


def _status_row(cn, real, pool, cid):
    fields = ["CLIENT_LIST", cn, real, pool, "10", "20", "now", "1700000000", cn, "", str(cid)]
    return "\t".join(fields)


def _marker(path, cn, pool, created):
    with open(path, "w") as f:
        f.write(
            f"common_name={cn}\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
            f"ifconfig_pool_remote_ip={pool}\ncreated={created}\n"
        )


def test_purges_only_stale_absent_pool(tmp_path):
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    status = tmp_path / "status.log"
    now = int(time.time())
    old = now - 25 * 3600

    fresh = sessions / "u1.10.8.0.1"
    stale_dead = sessions / "u2.10.8.0.2"
    stale_live = sessions / "u3.10.8.0.3"
    _marker(fresh, "u1", "10.8.0.1", now)
    _marker(stale_dead, "u2", "10.8.0.2", old)
    _marker(stale_live, "u3", "10.8.0.3", old)
    status.write_text("HEADER\tX\n" + _status_row("u3", "5.5.5.5:4000", "10.8.0.3", 9) + "\n")

    env = {
        **os.environ,
        "OVNODE_SESSIONS_DIR": str(sessions),
        "OVNODE_STATUS_FILE": str(status),
    }
    r = subprocess.run(
        [sys.executable, SCRIPT], capture_output=True, text=True, timeout=30, env=env
    )
    assert r.returncode == 0, r.stderr
    assert not stale_dead.exists(), "stale marker with a dead pool must be removed"
    assert fresh.exists(), "fresh marker must stay"
    assert stale_live.exists(), "stale marker with a live pool must stay"
    assert json.loads(r.stdout) == {"removed": 1, "kept": 2, "scanned": 3}
