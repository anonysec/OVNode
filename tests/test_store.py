# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Tests for the on-disk store: per-user folders + legacy migration."""

import json
import os

from core.openvpn import store


def test_user_folder_holds_all_state():
    """One folder per user: name, limit, disabled marker, cached profile."""
    cn = "9001"
    try:
        store.set_name(cn, "bob")
        store.set_limit(cn, 3)
        store.set_disabled(cn, True)

        d = store.user_dir(cn)
        assert sorted(os.listdir(d)) == ["disabled", "limit", "name"]
        assert store.get_name(cn) == "bob"
        assert store.get_limit(cn) == 3
        assert store.is_disabled(cn) is True

        store.set_disabled(cn, False)
        assert store.is_disabled(cn) is False

        store.delete_user(cn)
        assert not store.user_exists(cn)
    finally:
        store.delete_user(cn)


def test_store_rejects_path_traversal():
    import pytest

    for bad in ("../evil", "a/b", "", "x" * 65):
        with pytest.raises(ValueError):
            store.user_dir(bad)


def test_name_lookup_roundtrip():
    try:
        store.set_name("9002", "carol")
        assert store.name_map().get("9002") == "carol"
        assert store.cn_for_name("carol") == "9002"
        assert store.cn_for_name("nobody-here") is None
    finally:
        store.delete_user("9002")


def test_legacy_layout_migration():
    """clients/ + limits/ + disabled/ + ovnode-active/ + uid_map.json are
    absorbed into the ovnode tree, so restoring an old backup just works."""
    root = os.environ["OVNODE_OPENVPN_ROOT"]
    legacy = {
        "clients": os.path.join(root, "clients"),
        "limits": os.path.join(root, "limits"),
        "disabled": os.path.join(root, "disabled"),
        "active": os.path.join(root, "ovnode-active"),
    }
    for d in legacy.values():
        os.makedirs(d, exist_ok=True)

    try:
        with open(os.path.join(legacy["clients"], "uid_map.json"), "w") as f:
            json.dump({"7001": "dave"}, f)
        with open(os.path.join(legacy["clients"], "7001.ovpn"), "w") as f:
            f.write("client\n")
        with open(os.path.join(legacy["limits"], "7001"), "w") as f:
            f.write("2")
        open(os.path.join(legacy["disabled"], "7001"), "w").close()
        with open(os.path.join(legacy["active"], "7001.10.8.0.9"), "w") as f:
            f.write("common_name=7001\n")

        store.ensure_layout()

        assert store.get_name("7001") == "dave"
        assert store.get_limit("7001") == 2
        assert store.is_disabled("7001") is True
        with open(store.ovpn_path("7001")) as f:
            assert f.read() == "client\n"
        assert os.path.isfile(os.path.join(store.SESSIONS_DIR, "7001.10.8.0.9"))

        # Legacy locations are gone (moved, not copied).
        assert not os.path.exists(os.path.join(legacy["clients"], "uid_map.json"))
        for d in legacy.values():
            assert not os.path.isdir(d) or not os.listdir(d)

        # Re-running is a no-op and never clobbers migrated state.
        store.set_limit("7001", 5)
        store.ensure_layout()
        assert store.get_limit("7001") == 5
    finally:
        store.delete_user("7001")
        for d in legacy.values():
            if os.path.isdir(d):
                for e in os.listdir(d):
                    os.remove(os.path.join(d, e))
                os.rmdir(d)
        try:
            os.remove(os.path.join(store.SESSIONS_DIR, "7001.10.8.0.9"))
        except FileNotFoundError:
            pass


def test_set_limit_by_username_reaches_cn():
    """PUT /sync/user/limit may carry the panel USERNAME — the limit must
    land in the CN's folder, where the connect hook actually reads it."""
    from core.openvpn.users import set_user_limit

    try:
        store.set_name("9003", "erin")
        assert set_user_limit("erin", 4) is True
        assert store.get_limit("9003") == 4
    finally:
        store.delete_user("9003")
