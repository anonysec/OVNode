# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Every place the version is written must agree.

A missed bump is silent. Nothing but ``__version__`` is read at runtime, so a
stale ``manager.sh`` banner, README badge or package version ships without
failing a single check — which is exactly how ``manager.sh`` sat at an old
version until someone happened to read it.

The set below is the whole set. It is enumerated rather than discovered, so a
release that adds a new version spot still needs this list updated; the test
just stops the existing ones drifting.
"""

import re
from pathlib import Path

import pytest

from backend.version import __version__

REPO = Path(__file__).resolve().parent.parent

# (path, pattern) — the pattern must capture the version as group 1.
TEXT_SPOTS = [
    ("pyproject.toml", r'^version = "([^"]+)"'),
    ("install.sh", r'^VERSION="([^"]+)"'),
    ("manager.sh", r'^VERSION="([^"]+)"'),
    ("README.md", r"badge/version-([0-9][^-]*)"),
]


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize(("relative", "pattern"), TEXT_SPOTS, ids=[p for p, _ in TEXT_SPOTS])
def test_text_spot_matches_the_package_version(relative, pattern):
    match = re.search(pattern, _read(relative), re.MULTILINE)
    assert match, f"{relative} has no version matching {pattern!r}"
    assert match.group(1) == __version__, (
        f"{relative} says {match.group(1)}, backend/version.py says {__version__}"
    )


def test_changelog_has_an_entry_for_this_version():
    """The newest release heading must be the version being shipped."""
    headings = re.findall(r"^## ([0-9][0-9.]*) — ", _read("CHANGELOG.md"), re.MULTILINE)
    assert headings, "CHANGELOG.md has no '## X.Y.Z — date' heading"
    assert headings[0] == __version__, (
        f"CHANGELOG.md's newest entry is {headings[0]}, the version is {__version__}"
    )


def test_installer_and_manager_report_the_same_version():
    """Both are user-visible: the install banner and the `ovn` menu header."""
    install = re.search(r'^VERSION="([^"]+)"', _read("install.sh"), re.MULTILINE).group(1)
    manager = re.search(r'^VERSION="([^"]+)"', _read("manager.sh"), re.MULTILINE).group(1)
    assert install == manager, f"install.sh says {install}, manager.sh says {manager}"


def test_pyproject_parses_as_toml_and_agrees():
    """Read structurally, not by regex, so a formatting change stays caught."""
    import tomllib

    data = tomllib.loads(_read("pyproject.toml"))
    assert data["project"]["version"] == __version__
