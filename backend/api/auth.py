# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

import hashlib
import hmac
import json
import os
import time
from collections import OrderedDict
from threading import Lock

from fastapi import Header, HTTPException, Request, status

from backend.config import settings
from backend.logger import logger
from backend.openvpn.store import OVNODE_DIR

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


# ── panel pairing ────────────────────────────────────────────────────
#
# The API key says "you are allowed"; the pairing says "you are the owner".
# One panel owns a node at a time, so a second panel with a valid key is
# refused while the first one still holds the lease.
#
# The record is one small JSON file beside the rest of the node's own state
# (the ovnode tree, sandboxed by OVNODE_OPENVPN_ROOT in tests), so the CLI
# release is a `rm` and no parser, service or dependency is added.
_LEASE_SECONDS = 30 * 60
PAIRING_PATH = os.path.join(OVNODE_DIR, "state", "pairing.json")
_PANEL_HEADER = "x-panel-id"


def _load_pairing() -> dict | None:
    """The stored {panel_id, last_seen}, or None when there is none usable."""
    try:
        with open(PAIRING_PATH, encoding="utf-8") as fh:
            record = json.load(fh)
        panel_id = str(record.get("panel_id") or "").strip()
        last_seen = float(record.get("last_seen"))
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    if not panel_id:
        return None
    return {"panel_id": panel_id, "last_seen": last_seen}


def _save_pairing(panel_id: str, last_seen: float) -> None:
    from backend.openvpn.atomic import write_text_atomic

    payload = json.dumps({"panel_id": panel_id, "last_seen": last_seen})
    write_text_atomic(PAIRING_PATH, payload, mode=0o600)


def enforce_panel_pairing(request: Request | None) -> None:
    """Apply the single-panel lease for this keyed request.

    ``X-Panel-ID`` carries the calling panel's identity. Missing or empty is
    anonymous: allowed only while the node is unpaired (and takes no lease),
    rejected with 409 once paired — otherwise omitting the header would bypass
    the single-panel rule. A paired panel refreshes ``last_seen``; a foreign
    panel is 409 while the lease holds and takes over silently once it expires.
    """
    if request is None:
        return
    panel_id = (request.headers.get(_PANEL_HEADER) or "").strip()
    now = time.time()
    record = _load_pairing()
    if not panel_id:
        if record is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Node is paired with another panel. Wait for the 30-minute lease "
                    "or run `ovn auth disconnect` on this node."
                ),
            )
        return
    if record is not None and record["panel_id"] != panel_id:
        age = now - record["last_seen"]
        if age <= _LEASE_SECONDS:
            logger.warning(
                "Panel %s refused: paired with %s, lease holds for %.0fs more",
                panel_id,
                record["panel_id"],
                _LEASE_SECONDS - age,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Node is paired with another panel. Wait for the 30-minute lease "
                    "or run `ovn auth disconnect` on this node."
                ),
            )
        logger.warning(
            "Panel %s takes over from %s — lease expired %.0fs ago",
            panel_id,
            record["panel_id"],
            -age,
        )
    # Sync file IO on the event loop, same as every other store read here:
    # the record is a few dozen bytes, so this never waits a scheduler tick.
    # Concurrent pairers race on the last write; the lease makes the winner
    # the panel that keeps calling.
    _save_pairing(panel_id, now)


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
    # Pairing runs only after the key is proven: X-Panel-ID is identity, not
    # authentication, and only routes that reach this dependency are leased.
    enforce_panel_pairing(request)
    return key


async def check_api_key_heavy(key: str | None = Header(None), request: Request = None) -> str:
    """API-key check + tight rate limit for cert-issuing endpoints.

    A stuck panel gets 429 + Retry-After instead of queueing easyrsa forks.
    """
    await check_api_key(key, request)
    apply_heavy_limit(request)
    return key
