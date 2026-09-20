# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""install.sh and lib/common.sh must carry identical copies of shared helpers.

install.sh runs standalone (curl-pipe installs), so it duplicates the
library core. This test fails the suite on any drift between the two.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"
LIB = REPO / "lib" / "common.sh"

SHARED = [
    "line", "step", "info", "warn", "field", "sep",
    "json_escape", "die", "is_tty", "fancy", "spinner", "run", "try_run",
    "_masked_read", "ask", "confirm", "confirm_no",
    "is_port", "backup_dir", "wait_health",
    "env_get", "env_set", "systemctl_bounded",
    "tui_select",
    "generate_selfsigned", "ensure_acme", "issue_letsencrypt", "setup_tls",
    "emit_result", "primary_ip",
]


def extract(text: str, name: str) -> str:
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if re.match(rf"^{re.escape(name)}\(\)", ln))
    if lines[start].rstrip().endswith("}"):
        return lines[start]
    end = start
    while lines[end] != "}":
        end += 1
    return "\n".join(lines[start : end + 1])


def test_lib_exists():
    assert LIB.is_file(), "lib/common.sh missing"


def test_shared_helpers_in_sync():
    installer = INSTALLER.read_text(encoding="utf-8")
    lib = LIB.read_text(encoding="utf-8")
    drifted = [n for n in SHARED if extract(installer, n) != extract(lib, n)]
    assert not drifted, f"lib/common.sh out of sync with install.sh: {drifted}"


def test_lib_defines_kv_for_tls_menu():
    """node_tls_menu prints kv rows but install.sh never defined kv —
    the lib must provide it (moved(manager) code depends on it)."""
    lib = LIB.read_text(encoding="utf-8")
    assert re.search(r"^kv\(\)", lib, re.M), "lib/common.sh must define kv()"
    assert re.search(r"^node_name_from_env\(\)", lib, re.M), (
        "lib/common.sh must define node_name_from_env()"
    )


def test_manager_sources_lib_not_copies():
    manager = (REPO / "manager.sh").read_text(encoding="utf-8")
    assert "lib/common.sh" in manager
    for name in SHARED:
        assert not re.search(rf"^{re.escape(name)}\(\)", manager, re.M), (
            f"manager.sh duplicates lib function: {name}"
        )
