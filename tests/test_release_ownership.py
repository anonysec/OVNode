# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The release tarball must not carry, or restore, a foreign uid.

`git archive` on a CI runner bakes that runner's uid into the tarball, and the
installer extracts as root — so a plain `tar -xzf` restores it and the installed
tree ends up owned by a uid that does not exist on the target host. OVManager
fixed this at both ends; OVNode was forked before that fix, so the bug lived in
the packer and the extractor here simultaneously.

The extractor's flag is asserted as text because fetch_release is network-bound.
The root-gated test below proves the flag is what does the work.
"""

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"
RELEASE_WORKFLOW = REPO / ".github" / "workflows" / "release.yml"

FOREIGN_UID = 12345


def _fetch_release_body() -> str:
    """fetch_release's text, from its definition to the closing brace."""
    lines = INSTALLER.read_text(encoding="utf-8").splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("fetch_release()"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


def _tar(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["tar", *args], capture_output=True, text=True, check=check)


def test_the_extractor_ignores_archive_ownership():
    body = _fetch_release_body()
    assert "--no-same-owner" in body, (
        "fetch_release extracts without --no-same-owner, so a tarball from an "
        "older release restores the uid that built it"
    )
    assert "chown -R root:root" in body, (
        "the extracted tree's ownership must not depend on how it was built"
    )


def test_the_packer_zeroes_owner_and_group():
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "tar --owner=0 --group=0" in workflow, (
        "release.yml packs the tarball without --owner/--group, so the runner's "
        "uid is baked into every published artifact"
    )


@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="only root can restore an archive's numeric owners, so the bug is not observable",
)
def test_the_flag_is_what_stops_a_foreign_uid_being_restored(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x", encoding="utf-8")

    # Built the way release.yml builds it — a foreign uid baked in at pack time.
    archive = tmp_path / "release.tar.gz"
    _tar(
        f"--owner={FOREIGN_UID}",
        f"--group={FOREIGN_UID}",
        "-czf",
        str(archive),
        "-C",
        str(source),
        ".",
    )

    # If the archive stopped carrying a foreign uid, the assertions below would
    # pass for the wrong reason and this test would be silently vacuous.
    listing = _tar("-tvf", str(archive)).stdout
    assert f"{FOREIGN_UID}/{FOREIGN_UID}" in listing, (
        f"the test archive does not carry uid {FOREIGN_UID}; it can no longer detect the regression"
    )

    # Control: a plain extract as root really does restore the foreign uid, so
    # the guarded assertion is not vacuous either.
    unguarded = tmp_path / "unguarded"
    unguarded.mkdir()
    _tar("-xzf", str(archive), "-C", str(unguarded))
    assert (unguarded / "app.py").stat().st_uid == FOREIGN_UID, (
        "a plain root extract no longer restores the archive uid; this test is stale"
    )

    guarded = tmp_path / "guarded"
    guarded.mkdir()
    _tar("--no-same-owner", "-xzf", str(archive), "-C", str(guarded))
    assert (guarded / "app.py").stat().st_uid == 0
