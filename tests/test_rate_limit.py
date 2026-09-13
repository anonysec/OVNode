# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Rate-limiter contract: both buckets return (allowed, retry_after_s) and
both 429 responses carry a Retry-After header the panel honors."""

import time

import core.api.auth as auth


def _drain(bucket_fn, limit, key="rl-test-key"):
    results = [bucket_fn(key) for _ in range(limit + 1)]
    return results


def test_allowed_tuple_until_limit_then_retry_after():
    auth._ratelimit_buckets.clear()
    try:
        oks = _drain(auth._allowed, auth._MAX_REQUESTS)
        assert all(ok for ok, _ in oks[:-1])
        allowed, retry_after = oks[-1]
        assert allowed is False
        assert 1.0 <= retry_after <= auth._WINDOW
    finally:
        auth._ratelimit_buckets.clear()


def test_heavy_tuple_until_limit_then_retry_after():
    auth._heavy_buckets.clear()
    try:
        oks = _drain(auth._heavy_allowed, auth._HEAVY_MAX, key="rl-heavy-key")
        assert all(ok for ok, _ in oks[:-1])
        allowed, retry_after = oks[-1]
        assert allowed is False
        assert 1.0 <= retry_after <= auth._HEAVY_WINDOW
    finally:
        auth._heavy_buckets.clear()


def test_buckets_recover_after_window(monkeypatch):
    auth._ratelimit_buckets.clear()
    try:
        now = [time.monotonic()]
        monkeypatch.setattr(time, "monotonic", lambda: now[0])
        for _ in range(auth._MAX_REQUESTS):
            assert auth._allowed("rl-recover-key")[0] is True
        assert auth._allowed("rl-recover-key")[0] is False
        now[0] += auth._WINDOW + 1
        assert auth._allowed("rl-recover-key") == (True, 0.0)
    finally:
        auth._ratelimit_buckets.clear()
