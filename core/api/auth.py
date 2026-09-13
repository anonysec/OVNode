# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

import hashlib
import hmac
import time
from collections import OrderedDict
from threading import Lock

from fastapi import Header, HTTPException, Request, status

from core.config import settings
from core.logger import logger

# Simple in-memory per-key rate limiter.
# Prevents a misconfigured/compromised panel from hammering the node,
# which could saturate the OpenVPN management socket.
_WINDOW = 60  # seconds
_MAX_REQUESTS = 120  # per window

# Cert-issuing endpoints fork easyrsa (up to 120s each). A stuck panel
# looping create/delete could queue unbounded easyrsa processes and wedge
# the PKI lock — so these get a separate tight bucket with Retry-After.
# 60/min still stops a hot loop (vs. the 120/min general bucket) while
# leaving headroom for legit bursts the suite and bulk imports produce
# (sequential panel ops are ~1/s at most; the PKI lock serializes them).
_HEAVY_WINDOW = 60  # seconds
_HEAVY_MAX = 60  # cert-issuing requests per window


_ratelimit_lock = Lock()
_ratelimit_buckets: OrderedDict[str, list[float]] = OrderedDict()
_heavy_buckets: OrderedDict[str, list[float]] = OrderedDict()
_MAX_BUCKETS = 10_000


def _prune(buckets: OrderedDict[str, list[float]], now: float, window: float) -> None:
    stale = [k for k, values in buckets.items() if not values or now - values[-1] >= window]
    for stale_key in stale:
        buckets.pop(stale_key, None)
    while len(buckets) >= _MAX_BUCKETS:
        buckets.popitem(last=False)


def _allowed(api_key: str) -> bool:
    now = time.monotonic()
    # Do not retain attacker-controlled API-key strings in memory.
    key = hashlib.sha256(str(api_key).encode()).hexdigest()[:32]
    with _ratelimit_lock:
        _prune(_ratelimit_buckets, now, _WINDOW)
        bucket = [ts for ts in _ratelimit_buckets.get(key, []) if now - ts < _WINDOW]
        if len(bucket) >= _MAX_REQUESTS:
            _ratelimit_buckets[key] = bucket
            return False
        bucket.append(now)
        _ratelimit_buckets[key] = bucket
    return True


def _heavy_allowed(api_key: str) -> tuple[bool, float]:
    """Tight bucket for cert-issuing endpoints. Returns (allowed, retry_after_s)."""
    now = time.monotonic()
    key = hashlib.sha256(str(api_key).encode()).hexdigest()[:32]
    with _ratelimit_lock:
        _prune(_heavy_buckets, now, _HEAVY_WINDOW)
        bucket = [ts for ts in _heavy_buckets.get(key, []) if now - ts < _HEAVY_WINDOW]
        if len(bucket) >= _HEAVY_MAX:
            retry_after = max(1.0, _HEAVY_WINDOW - (now - bucket[0]))
            _heavy_buckets[key] = bucket
            return False, retry_after
        bucket.append(now)
        _heavy_buckets[key] = bucket
    return True, 0.0


async def check_api_key(key: str = Header(...), request: Request = None) -> str:
    """Check if the provided API key is valid (constant-time compare)."""
    ip = request.client.host if request is not None and request.client else "?"
    if not _allowed(key):
        logger.warning("Rate limit exceeded for API key from %s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )
    if not hmac.compare_digest(key, settings.api_key):
        logger.warning("Invalid API key rejected from %s", ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return key


async def check_api_key_heavy(key: str = Header(...), request: Request = None) -> str:
    """API-key check + tight rate limit for cert-issuing endpoints.

    easyrsa forks are the most expensive thing the node does; a stuck panel
    must get 429 + Retry-After instead of queueing unbounded processes.
    """
    await check_api_key(key, request)
    ok, retry_after = _heavy_allowed(key)
    if not ok:
        ip = request.client.host if request is not None and request.client else "?"
        logger.warning("Cert-issuing rate limit exceeded from %s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many certificate operations — slow down",
            headers={"Retry-After": str(int(retry_after))},
        )
    return key
