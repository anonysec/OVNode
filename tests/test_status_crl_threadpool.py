"""GET /sync/status must never fork easyrsa on the event loop.

CRL freshness is re-checked once a day, and the check runs `easyrsa gen-crl`
(up to a 120s subprocess). Done inline from the async route, that one poll
stalls the single uvicorn worker and every other panel call queues behind it:
usage, sessions and disconnect all wait on a certificate-maintenance fork.

The offload is the whole fix, so it is asserted at the seam other blocking PKI
work already uses (see test_threadpool_and_rollback.py).
"""

from fastapi.testclient import TestClient


def _client():
    from backend.app import api
    from backend.config import settings

    return TestClient(api), {"key": settings.api_key}


def _clear_limits():
    from backend.api import auth

    auth._ratelimit_buckets.clear()
    auth._heavy_buckets.clear()


def test_status_offloads_the_crl_check_to_the_threadpool(monkeypatch):
    from fastapi.concurrency import run_in_threadpool as real_run_in_threadpool

    from backend.api.routes import system as routes

    threaded: list[str] = []

    async def recording_run_in_threadpool(fn, *args, **kwargs):
        threaded.append(getattr(fn, "__name__", repr(fn)))
        return await real_run_in_threadpool(fn, *args, **kwargs)

    def fake_ensure_crl():
        return True

    monkeypatch.setattr(routes, "run_in_threadpool", recording_run_in_threadpool)
    monkeypatch.setattr(routes, "_crl_last_check", 0.0, raising=False)
    monkeypatch.setattr("backend.openvpn.pki._ensure_crl", fake_ensure_crl, raising=False)

    _clear_limits()
    c, headers = _client()
    resp = c.get("/sync/status", headers=headers)
    assert resp.status_code == 200, resp.text
    assert any("crl" in name for name in threaded), (
        f"the CRL refresh forks easyrsa and must be offloaded; threaded={threaded}"
    )


def test_status_still_answers_when_the_crl_check_explodes(monkeypatch):
    """Renewal is best-effort: a broken PKI must not take /sync/status down."""
    from backend.api.routes import system as routes

    def boom():
        raise RuntimeError("easyrsa is missing")

    monkeypatch.setattr(routes, "_crl_last_check", 0.0, raising=False)
    monkeypatch.setattr("backend.openvpn.pki._ensure_crl", boom, raising=False)

    _clear_limits()
    c, headers = _client()
    resp = c.get("/sync/status", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["success"] is True


def test_the_crl_check_is_rate_limited_to_once_a_day(monkeypatch):
    """It is a daily maintenance fork, not a per-poll one."""
    import time

    from backend.api.routes import system as routes

    calls: list[float] = []

    def fake_ensure_crl():
        calls.append(time.monotonic())
        return True

    monkeypatch.setattr(routes, "_crl_last_check", time.monotonic(), raising=False)
    monkeypatch.setattr("backend.openvpn.pki._ensure_crl", fake_ensure_crl, raising=False)

    _clear_limits()
    c, headers = _client()
    for _ in range(3):
        assert c.get("/sync/status", headers=headers).status_code == 200

    assert calls == [], "a recent check must suppress further forks"
