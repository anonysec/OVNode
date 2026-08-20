# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

import hashlib
import hmac
import time
from collections import OrderedDict
from threading import Lock

from fastapi import Header, HTTPException, status

from core.config import settings
from core.logger import logger

# Simple in-memory per-key rate limiter.
# Prevents a misconfigured/compromised panel from hammering the node,
# which could saturate the OpenVPN management socket.
_WINDOW = 60  # seconds
_MAX_REQUESTS = 120  # per window


_ratelimit_lock = Lock()
_ratelimit_buckets: OrderedDict[str, list[float]] = OrderedDict()
_MAX_BUCKETS = 10_000


def _allowed(api_key: str) -> bool:
    now = time.monotonic()
    # Do not retain attacker-controlled API-key strings in memory.
    key = hashlib.sha256(str(api_key).encode()).hexdigest()[:32]
    with _ratelimit_lock:
        stale = [
            k for k, values in _ratelimit_buckets.items()
            if not values or now - values[-1] >= _WINDOW
        ]
        for stale_key in stale:
            _ratelimit_buckets.pop(stale_key, None)
        while len(_ratelimit_buckets) >= _MAX_BUCKETS and key not in _ratelimit_buckets:
            _ratelimit_buckets.popitem(last=False)
        bucket = [ts for ts in _ratelimit_buckets.get(key, []) if now - ts < _WINDOW]
        if len(bucket) >= _MAX_REQUESTS:
            _ratelimit_buckets[key] = bucket
            return False
        bucket.append(now)
        _ratelimit_buckets[key] = bucket
    return True


async def check_api_key(key: str = Header(...)) -> str:
    """Check if the provided API key is valid (constant-time compare)."""
    if not _allowed(key):
        logger.warning("Rate limit exceeded for API key")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )
    if not hmac.compare_digest(key, settings.api_key):
        logger.warning("Invalid API key rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return key
