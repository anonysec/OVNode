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

# In-memory per-client rate limiter, so a misconfigured or compromised panel
# cannot hammer the node and saturate the OpenVPN management socket.
#
# Keyed by CLIENT ADDRESS, not by the submitted API key: keying on the
# attacker-supplied value gave every guessed key a fresh bucket, so brute
# force was unlimited and a flood of bogus keys evicted the real caller's.
_WINDOW = 60  # seconds
_MAX_REQUESTS = 120  # per client per window
_GLOBAL_MAX = 600  # across all clients per window
_GLOBAL_KEY = "__global__"

# Cert-issuing endpoints fork easyrsa (up to 120s each), so a stuck panel
# looping create/delete could queue unbounded processes and wedge the PKI
# lock. 60/min still stops a hot loop while leaving headroom for legit
# bursts (sequential panel ops are ~1/s at most).
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


def _global_allowed(now: float) -> tuple[bool, float]:
    """Ceiling across all clients, kept in the same dict so tests that clear
    ``_ratelimit_buckets`` reset it too."""
    hits = [ts for ts in _ratelimit_buckets.get(_GLOBAL_KEY, []) if now - ts < _WINDOW]
    if len(hits) >= _GLOBAL_MAX:
        retry_after = max(1.0, _WINDOW - (now - hits[0])) if hits else 1.0
        _ratelimit_buckets[_GLOBAL_KEY] = hits
        return False, retry_after
    hits.append(now)
    _ratelimit_buckets[_GLOBAL_KEY] = hits
    return True, 0.0


def _allowed(api_key: str) -> tuple[bool, float]:
    now = time.monotonic()
    # Do not retain attacker-controlled API-key strings in memory.
    key = hashlib.sha256(str(api_key).encode()).hexdigest()[:32]
    with _ratelimit_lock:
        _prune(_ratelimit_buckets, now, _WINDOW)
        ok, retry_after = _global_allowed(now)
        if not ok:
            return False, retry_after
        bucket = [ts for ts in _ratelimit_buckets.get(key, []) if now - ts < _WINDOW]
        if len(bucket) >= _MAX_REQUESTS:
            retry_after = max(1.0, _WINDOW - (now - bucket[0])) if bucket else 1.0
            _ratelimit_buckets[key] = bucket
            return False, retry_after
        bucket.append(now)
        _ratelimit_buckets[key] = bucket
    return True, 0.0


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


def _client_key(request: Request | None) -> str:
    """Rate-limit key: the connecting address, never the submitted secret."""
    return request.client.host if request is not None and request.client else "?"


def apply_heavy_limit(request: Request | None) -> None:
    """Charge one heavy request for this client (used on cert-issuing paths).

    Public so the lazy ``download`` route can charge only its cold
    (cert-minting) path instead of gating every cached download.
    """
    ok, retry_after = _heavy_allowed(_client_key(request))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many certificate operations — slow down",
            headers={"Retry-After": str(int(retry_after))},
        )


async def check_api_key(key: str | None = Header(None), request: Request = None) -> str:
    """Check if the provided API key is valid (constant-time compare).

    The header is optional in the signature so an omitting request reaches
    this function: an absent credential is a 401, not the validator's 422.
    That 401 comes before rate-limit accounting, so a caller that never sends
    a key gets the diagnostic instead of a 429 that hides it.
    """
    if not key:
        logger.warning("Missing API key rejected from %s", _client_key(request))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )
    ip = _client_key(request)
    ok, retry_after = _allowed(ip)
    if not ok:
        logger.warning("Rate limit exceeded for client %s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(int(retry_after))},
        )
    # Encode both sides: compare_digest raises TypeError on non-ASCII str,
    # and header bytes are latin-1-decoded — raw HTTP could carry 0x80-0xFF.
    if not hmac.compare_digest(key.encode("utf-8", "ignore"), settings.api_key.encode("utf-8")):
        logger.warning("Invalid API key rejected from %s", ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return key


async def check_api_key_heavy(key: str | None = Header(None), request: Request = None) -> str:
    """API-key check + tight rate limit for cert-issuing endpoints.

    A stuck panel gets 429 + Retry-After instead of queueing easyrsa forks.
    """
    await check_api_key(key, request)
    apply_heavy_limit(request)
    return key
