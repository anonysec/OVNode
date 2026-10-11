# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Limiter key is the connecting address, never the submitted secret —
so spraying distinct keys from one IP spends one shared bucket."""

import backend.api.auth as auth


def test_rate_limit_keyed_by_ip_not_secret():
    auth._ratelimit_buckets.clear()
    try:
        for _ in range(auth._MAX_REQUESTS):
            ok, _ = auth._allowed("same-ip")
            assert ok
        ok, _ = auth._allowed("same-ip")
        assert not ok
    finally:
        auth._ratelimit_buckets.clear()


def test_heavy_rate_limit_keyed_by_ip_not_secret():
    auth._heavy_buckets.clear()
    try:
        for _ in range(auth._HEAVY_MAX):
            ok, _ = auth._heavy_allowed("same-ip")
            assert ok
        ok, _ = auth._heavy_allowed("same-ip")
        assert not ok
    finally:
        auth._heavy_buckets.clear()
