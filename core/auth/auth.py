import hmac
import time
from collections import defaultdict
from threading import Lock

from fastapi import Header, HTTPException, status

from core.config import settings
from core.logger import logger

# Simple in-memory per-key rate limiter.
# Prevents a misconfigured/compromised panel from hammering the node,
# which could saturate the OpenVPN management socket.
_KEY = "_ovnode_ratelimit"
_WINDOW = 60  # seconds
_MAX_REQUESTS = 120  # per window


_ratelimit_locks = defaultdict(Lock)
_ratelimit_buckets: dict[str, list[float]] = {}


def _allowed(api_key: str) -> bool:
    now = time.monotonic()
    key = str(api_key)
    with _ratelimit_locks[key]:
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
