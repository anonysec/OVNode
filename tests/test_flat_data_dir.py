# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The node's data lives at /var/lib/ovnode, not /var/lib/ovnode/<name>.

It used to be written as ``${DATA_BASE}/${NODE_NAME}`` in seventeen places,
which is a layout for several nodes on one host that nothing ever implemented —
there is one NODE_NAME, one service, one agent. Flattening it is a data
migration on every existing install, so the cases below are run against real
directories rather than asserted from the source.

The one that matters most is :func:`test_it_refuses_to_merge`, because the
failure it prevents is silent: two directories holding the same filename, and a
migration that picks one, gives a node back with the wrong API key.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LIB = REPO / "scripts" / "lib"

RUNNER = """\
set -Eeuo pipefail
APP_DIR={app}/opt
DATA_BASE={app}/data
NODE_NAME=ovnode
EX_OK=0 EX_ERROR=1 EX_USAGE=2
. "{app}/opt/scripts/lib/common.sh"
. "{app}/opt/scripts/lib/render.sh"
export NO_COLOR=1 TERM=dumb
# `|| rc=$?` rather than letting the failure end the script: set -e would abort
# before the echo, so a refused migration would be indistinguishable from a
# runner that never called the function — which is how the first version of
# this test passed against a migration that silently did nothing.
rc=0
migrate_flat_data_dir || rc=$?
echo "rc=$rc"
"""


def _install(root: Path, *, data_dir: str | None = None, node_name: str = "ovnode") -> Path:
    app = root / "opt"
    (app / "scripts" / "lib").mkdir(parents=True)
    for lib in LIB.glob("*.sh"):
        (app / "scripts" / "lib" / lib.name).write_text(lib.read_text(encoding="utf-8"))
    (app / "scripts" / "lib" / "doctor.sh").write_text(
        (LIB / "doctor.sh").read_text(encoding="utf-8")
    )
    declared = data_dir if data_dir is not None else f"{root}/data/{node_name}"
    (app / ".env").write_text(
        f"NODE_NAME={node_name}\nDATA_DIR={declared}\nSERVICE_PORT=2083\nAPI_KEY=abc123\n",
        encoding="utf-8",
    )
    (app / ".env").chmod(0o600)
    return app


def _migrate(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", RUNNER.format(app=root)],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _legacy(root: Path, **files: str) -> Path:
    legacy = root / "data" / "ovnode"
    legacy.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        target = legacy / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return legacy


# ── the happy path ──────────────────────────────────────────────────────


def test_it_moves_the_data_up_and_repoints_env(tmp_path):
    _install(tmp_path)
    _legacy(tmp_path, state="{}", key="secret")
    out = _migrate(tmp_path)
    assert "rc=0" in out.stdout, out.stdout + out.stderr

    assert (tmp_path / "data" / "state").read_text() == "{}"
    assert (tmp_path / "data" / "key").read_text() == "secret"
    assert not (tmp_path / "data" / "ovnode").exists(), "the old directory must be gone"
    assert f"DATA_DIR={tmp_path}/data" in (tmp_path / "opt" / ".env").read_text()


def test_it_keeps_the_env_mode_and_owner(tmp_path):
    """`.env` holds the API key. A migration that rewrites it 0644 has just
    handed the node's credential to every local account."""
    _install(tmp_path)
    (tmp_path / "opt" / ".env").chmod(0o600)
    _legacy(tmp_path, state="{}")
    _migrate(tmp_path)
    assert (tmp_path / "opt" / ".env").stat().st_mode & 0o777 == 0o600


def test_it_leaves_sibling_state_alone(tmp_path):
    """`update-state.json` and the operation lock live at the base, beside the
    node's data, and an update in progress depends on them staying put."""
    _install(tmp_path)
    _legacy(tmp_path, state="{}")
    (tmp_path / "data" / "update-state.json").write_text('{"phase":"staging"}', encoding="utf-8")
    _migrate(tmp_path)
    assert json_load(tmp_path / "data" / "update-state.json")["phase"] == "staging"


def test_it_carries_dotfiles_and_nested_directories(tmp_path):
    _install(tmp_path)
    _legacy(tmp_path)
    (tmp_path / "data" / "ovnode" / ".hidden").write_text("h", encoding="utf-8")
    (tmp_path / "data" / "ovnode" / "sub").mkdir()
    (tmp_path / "data" / "ovnode" / "sub" / "deep").write_text("d", encoding="utf-8")
    _migrate(tmp_path)
    assert (tmp_path / "data" / ".hidden").read_text() == "h"
    assert (tmp_path / "data" / "sub" / "deep").read_text() == "d"


# ── the cases that must not lose data ────────────────────────────────────


def test_it_refuses_to_merge(tmp_path):
    """Two directories, one filename. Guessing is how a node comes back with
    the wrong API key, so it stops and says which file."""
    _install(tmp_path)
    _legacy(tmp_path, state="OLD")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "state").write_text("NEW", encoding="utf-8")

    out = _migrate(tmp_path)
    # render_fail writes to stderr — the renderer's contract, shared with every
    # failure in both repos.
    assert "rc=1" in out.stdout, out.stdout + out.stderr
    assert "refusing to merge" in out.stderr
    assert "state" in out.stderr, "the conflict must be named"

    assert (tmp_path / "data" / "ovnode" / "state").read_text() == "OLD"
    assert (tmp_path / "data" / "state").read_text() == "NEW"
    assert f"DATA_DIR={tmp_path}/data/ovnode" in (tmp_path / "opt" / ".env").read_text()


def test_it_is_idempotent(tmp_path):
    """`ovn update` runs this on every update. A second run must be a no-op, and
    must not re-report work that is already done."""
    _install(tmp_path)
    _legacy(tmp_path, state="{}")
    assert "rc=0" in _migrate(tmp_path).stdout
    out = _migrate(tmp_path)
    assert "rc=0" in out.stdout
    assert "moved node data" not in out.stdout, out.stdout
    assert (tmp_path / "data" / "state").read_text() == "{}"


def test_an_already_flat_install_is_left_alone(tmp_path):
    _install(tmp_path, data_dir=f"{tmp_path}/data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "state").write_text("{}", encoding="utf-8")
    out = _migrate(tmp_path)
    assert "rc=0" in out.stdout
    assert "moved" not in out.stdout, out.stdout
    assert f"DATA_DIR={tmp_path}/data" in (tmp_path / "opt" / ".env").read_text()


def test_a_fresh_install_with_no_env_does_nothing(tmp_path):
    """There is no legacy directory and no .env — a first install. It must not
    invent either."""
    (tmp_path / "opt" / "scripts" / "lib").mkdir(parents=True)
    for lib in LIB.glob("*.sh"):
        (tmp_path / "opt" / "scripts" / "lib" / lib.name).write_text(
            lib.read_text(encoding="utf-8")
        )
    out = _migrate(tmp_path)
    assert "rc=0" in out.stdout
    assert not (tmp_path / "opt" / ".env").exists()


# ── the path is answered in one place ────────────────────────────────────


def test_no_call_site_builds_the_nested_path_by_hand():
    """The layout question belongs in node_data_dir(), not in seventeen places
    that can disagree — which is exactly how it drifted before."""
    import re

    pattern = re.compile(r'DATA_BASE[/}]\s*[/"{]*\$\{?(NODE_NAME|node)')
    offenders = {}
    for path in (REPO / "install.sh", REPO / "manager.sh", *LIB.glob("*.sh")):
        lines = path.read_text(encoding="utf-8").splitlines()
        in_legacy = False
        hits = []
        for i, line in enumerate(lines, 1):
            # A comment naming the old form is documentation, not a call site.
            if line.lstrip().startswith("#"):
                continue
            if "node_legacy_data_dir()" in line:
                in_legacy = not line.rstrip().endswith("{")
            if not in_legacy and pattern.search(line):
                hits.append(i)
        if hits:
            offenders[path.name] = hits
    assert not offenders, f"the nested path is built by hand again: {offenders}"


def test_node_data_dir_prefers_the_declaration(tmp_path):
    """`.env` declares it, the way it declares the certificate paths. An install
    that names a directory keeps it."""
    app = _install(tmp_path, data_dir="/somewhere/custom")
    out = subprocess.run(
        ["bash", "-c", f'APP_DIR={app} DATA_BASE={tmp_path}/data\n'
                      f'. "{app}/scripts/lib/common.sh"; node_data_dir'],
        capture_output=True, text=True, timeout=30, env={**os.environ, "NO_COLOR": "1"},
    )
    assert out.stdout.strip() == "/somewhere/custom", out.stdout + out.stderr


def test_node_data_dir_falls_back_to_the_base(tmp_path):
    app = _install(tmp_path)
    (app / ".env").unlink()
    out = subprocess.run(
        ["bash", "-c", f'APP_DIR={app} DATA_BASE={tmp_path}/data\n'
                      f'. "{app}/scripts/lib/common.sh"; node_data_dir'],
        capture_output=True, text=True, timeout=30, env={**os.environ, "NO_COLOR": "1"},
    )
    assert out.stdout.strip() == f"{tmp_path}/data", out.stdout + out.stderr


def json_load(path: Path) -> dict:
    import json

    return json.loads(path.read_text(encoding="utf-8"))
