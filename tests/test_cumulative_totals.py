# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Cumulative usage totals: monotonic across restarts, never 500 on garbage.

The panel cursor does exactly-once accounting against these totals, so the
node's guarantee is narrow and absolute: banked per-user bytes survive a
restart unchanged, a second poll without new traffic returns the same
numbers (no zeroing), and a corrupt bank file reads as 0 + a warning —
never an exception, never a 500.
"""

import os

import pytest

from backend.logger import recent_logs


@pytest.fixture
def fresh_store(monkeypatch):
    """Wipe the store's module state (= a fresh process) and stub live
    sessions away: these tests are about banked totals only.

    Uses the shared sandbox tree, NOT monkeypatched path constants:
    backend.api.auth freezes OVNODE_DIR at import, so a client built while
    the constants are patched would keep the dead tmp path forever.
    """
    import backend.openvpn.status as status
    from backend.openvpn import store

    monkeypatch.setattr(status, "parse_usage", lambda: {"users": {}, "sessions": {}})
    store._usage_cache = None
    store._name_cache = None
    yield store
    # Leave None, not the pre-test tuple: a restored stale cache would leak
    # into whatever test runs next (its TTL may not have expired).
    store._usage_cache = None
    store._name_cache = None


def _bank(store, cn: str, name: str, total: str) -> str:
    os.makedirs(store.USAGE_DIR, exist_ok=True)
    store.set_name(cn, name)
    path = os.path.join(store.USAGE_DIR, cn)
    with open(path, "w", encoding="utf-8") as f:
        f.write(total)
    return path


def test_totals_survive_restart(fresh_store):
    """Banked bytes are on disk; a restart (module state wiped) re-reads
    the same cumulative totals — the panel cursor sees no regression."""
    from backend.openvpn import users as um

    store = fresh_store
    try:
        _bank(store, "cumrestart", "restart-user", "123456\n")

        first = um.get_users_usage()["totals"]

        # Simulate an agent restart: all in-memory state gone, files remain.
        store._usage_cache = None
        store._name_cache = None

        second = um.get_users_usage()["totals"]
        assert first == second == {"restart-user": 123456}
    finally:
        store.delete_user("cumrestart")


def test_double_read_without_traffic_is_identical(fresh_store):
    """Two polls with no new bytes return identical totals and leave the
    bank file untouched — proves the read path never zeroes."""
    from backend.openvpn import users as um

    store = fresh_store
    try:
        path = _bank(store, "cumdouble", "double-user", "555\n")

        first = um.get_users_usage()["totals"]
        store._usage_cache = None  # force a fresh disk read, not a cache hit
        second = um.get_users_usage()["totals"]

        assert first == second == {"double-user": 555}
        with open(path, encoding="utf-8") as f:
            assert f.read().strip() == "555"
    finally:
        store.delete_user("cumdouble")


def test_corrupt_usage_file_is_zero_with_warning(fresh_store):
    """Corrupt bank file → user reads as 0 + a warning; GET /sync/usage
    stays 200. A corrupt file must never take the panel poll down."""
    from fastapi.testclient import TestClient

    from backend.app import api
    from backend.config import settings

    store = fresh_store
    try:
        path = _bank(store, "cumcorrupt", "corrupt-user", "1\n")
        with open(path, "wb") as f:
            f.write(b"\xff\xfe not-a-number")

        assert store.accumulated_usage("cumcorrupt") == 0

        client = TestClient(api, raise_server_exceptions=False)
        r = client.get("/sync/usage", headers={"key": settings.api_key})
        assert r.status_code == 200
        assert r.json()["data"]["totals"].get("corrupt-user", 0) == 0

        messages = [rec["message"] for rec in recent_logs(min_level="WARNING", limit=50)]
        assert any("corrupt usage" in m for m in messages)
    finally:
        store.delete_user("cumcorrupt")
