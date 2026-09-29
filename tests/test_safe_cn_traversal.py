# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""``_safe_cn`` must reject the values that make it unsafe as a path component.

The regex ``^[A-Za-z0-9._-]{1,64}$`` accepts ``..`` and ``.``, both of which
match the character class but are path components rather than names:
``os.path.join(USERS_DIR, "..")`` resolves to the parent of the users tree.

Every route happens to validate the id before this is reached, so it is not
currently reachable — which is exactly why it is worth closing. This is the
last line of defence for any future caller that does not.
"""

import os

import pytest

from core.openvpn.store import USERS_DIR, _safe_cn, user_dir


@pytest.mark.parametrize("bad", ["..", ".", "", "  "])
def test_rejects_path_components(bad):
    with pytest.raises(ValueError):
        _safe_cn(bad)


@pytest.mark.parametrize("bad", ["-flag", "--help"])
def test_rejects_a_leading_dash(bad):
    """A CN reaches easyrsa's argv, where a leading dash is an option."""
    with pytest.raises(ValueError):
        _safe_cn(bad)


def test_a_leading_dot_is_allowed():
    """The store keeps its own bookkeeping as `.lock.<cn>`.

    A blanket dotfile ban looked like tightening but broke the usage scan,
    which lists the directory and matches entries against the same pattern.
    """
    assert _safe_cn(".hidden") == ".hidden"


def test_the_usage_scan_ignores_its_own_lock_files():
    """`.lock.<cn>` matches the key pattern, so the scan must skip it by name."""
    from core.openvpn import store

    real = store.accumulated_usage
    seen: list[str] = []
    try:
        store.accumulated_usage = lambda cn, *a, **k: seen.append(cn) or None
        store.all_accumulated_usage()
    finally:
        store.accumulated_usage = real
    assert not [c for c in seen if c.startswith(".lock.")], f"lock files treated as users: {seen}"


@pytest.mark.parametrize("bad", ["a/b", "a\\b", "a\x00b"])
def test_rejects_separators_and_nul(bad):
    with pytest.raises(ValueError):
        _safe_cn(bad)


@pytest.mark.parametrize("good", ["alice", "user_1", "42", "a.b", "a-b", "A" * 64])
def test_still_accepts_real_names(good):
    assert _safe_cn(good) == good


def test_user_dir_never_escapes_the_users_tree():
    """The property that matters: the resolved path stays inside USERS_DIR."""
    root = os.path.realpath(USERS_DIR)
    for candidate in ("..", "../.."):
        try:
            resolved = os.path.realpath(user_dir(candidate))
        except ValueError:
            continue  # rejected, which is the point
        assert resolved.startswith(root + os.sep), (
            f"{candidate!r} resolved outside {root}: {resolved}"
        )
