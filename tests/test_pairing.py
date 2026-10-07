# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Single-panel pairing: the first panel that calls a keyed route with an
``X-Panel-ID`` owns the node.

The API key authenticates; the pairing decides which panel may use it. A
foreign panel is refused while the first one holds the 30-minute lease, takes
over once it expires, and ``ovn auth disconnect`` (tests/test_manager_sh.py)
releases it by hand. Routes without the API-key dependency — /sync/health —
are outside the contract entirely.
"""

import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.openvpn.store import OVNODE_DIR

PANEL_A = "panel-aaaaaaaa-1111"
PANEL_B = "panel-bbbbbbbb-2222"
LEASE = 30 * 60
KEY = {"key": settings.api_key}
PAIRING = os.path.join(OVNODE_DIR, "state", "pairing.json")


def _clear() -> None:
    try:
        os.remove(PAIRING)
    except FileNotFoundError:
        pass


def _record() -> dict:
    with open(PAIRING, encoding="utf-8") as fh:
        return json.load(fh)


def _seed(panel_id: str, last_seen: float) -> None:
    os.makedirs(os.path.dirname(PAIRING), exist_ok=True)
    with open(PAIRING, "w", encoding="utf-8") as fh:
        json.dump({"panel_id": panel_id, "last_seen": last_seen}, fh)


@pytest.fixture
def client():
    from backend.app import api

    _clear()
    yield TestClient(api)
    _clear()


def _keyed(client: TestClient, panel_id: str | None = None):
    """A keyed GET on a leased route — /sync/status is the panel's poll."""
    headers = dict(KEY)
    if panel_id is not None:
        headers["X-Panel-ID"] = panel_id
    return client.get("/sync/status", headers=headers)


def test_first_contact_pairs_the_calling_panel(client):
    r = _keyed(client, PANEL_A)
    assert r.status_code == 200, r.text
    record = _record()
    assert record["panel_id"] == PANEL_A
    assert record["last_seen"] == pytest.approx(time.time(), abs=60)


def test_same_panel_refreshes_the_lease(client):
    stale = time.time() - 600
    _seed(PANEL_A, stale)
    assert _keyed(client, PANEL_A).status_code == 200
    assert _record()["last_seen"] > stale + 590


def test_foreign_panel_is_refused_while_the_lease_holds(client):
    _seed(PANEL_A, time.time() - 60)
    r = _keyed(client, PANEL_B)
    assert r.status_code == 409
    assert r.json()["msg"] == (
        "Node is paired with another panel. Wait for the 30-minute lease "
        "or run `ovn auth disconnect` on this node."
    )
    # Refused means refused: the loser does not touch the record.
    assert _record()["panel_id"] == PANEL_A


def test_expired_lease_lets_the_new_panel_take_over_silently(client):
    _seed(PANEL_A, time.time() - (LEASE + 1))
    r = _keyed(client, PANEL_B)
    assert r.status_code == 200, r.text
    assert _record()["panel_id"] == PANEL_B


def test_missing_or_empty_header_is_anonymous(client):
    # No pairing exists: an anonymous call takes no lease and leaves no record.
    assert _keyed(client).status_code == 200
    assert not os.path.exists(PAIRING)

    # Paired already: anonymous is refused (otherwise omitting the header
    # would bypass the single-panel rule) and leaves the record untouched.
    seeded = time.time() - 600
    _seed(PANEL_A, seeded)
    for headers in ({**KEY}, {**KEY, "X-Panel-ID": ""}, {**KEY, "X-Panel-ID": "   "}):
        r = client.get("/sync/status", headers=headers)
        assert r.status_code == 409
        assert "paired with another panel" in r.json()["msg"]
    assert _record() == {"panel_id": PANEL_A, "last_seen": seeded}


def test_an_invalid_key_never_reaches_pairing(client):
    r = client.get("/sync/status", headers={"key": "wrong-key-wrong-key", "X-Panel-ID": PANEL_B})
    assert r.status_code == 401
    assert not os.path.exists(PAIRING)


def test_health_is_unaffected_by_pairing(client):
    before = time.time()
    _seed(PANEL_A, before)
    r = client.get("/sync/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert _record() == {"panel_id": PANEL_A, "last_seen": before}


def test_cleared_pairing_pairs_the_next_panel(client):
    """What `ovn auth disconnect` does, from the agent's side: the record is
    gone, so the next panel to call is the new owner at once."""
    _seed(PANEL_A, time.time())
    _clear()
    assert _keyed(client, PANEL_B).status_code == 200
    assert _record()["panel_id"] == PANEL_B
