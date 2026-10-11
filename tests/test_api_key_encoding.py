# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""API-key header encoding: 0x80-0xFF header bytes must 401, and no input
may be dropped on the way to the compare."""

import asyncio
import os

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import config as c
from backend.api.auth import check_api_key
from backend.app import api
from backend.openvpn.store import OVNODE_DIR

PAIRING = os.path.join(OVNODE_DIR, "state", "pairing.json")


@pytest.fixture
def client():
    def _clear() -> None:
        try:
            os.remove(PAIRING)
        except FileNotFoundError:
            pass

    _clear()
    yield TestClient(api)
    _clear()


def _call(key: str) -> str:
    try:
        asyncio.run(check_api_key(key, None))
    except HTTPException as exc:
        return exc.status_code
    return "allowed"


def test_non_utf8_header_byte_is_401(client, monkeypatch):
    monkeypatch.setattr(c.settings, "api_key", "correct-key")
    r = client.get("/sync/status", headers=[(b"key", b"correct-key\xff")])
    assert r.status_code == 401


def test_unencodable_key_is_401_not_dropped(monkeypatch):
    monkeypatch.setattr(c.settings, "api_key", "correct-key")
    # "utf-8 ignore" dropped the unencodable byte and compared equal.
    assert _call("correct-key\udcff") == 401


def test_valid_key_passes_auth(client, monkeypatch):
    monkeypatch.setattr(c.settings, "api_key", "correct-key")
    r = client.get("/sync/status", headers={"key": "correct-key"})
    assert r.status_code in (200, 403, 422)


def test_wrong_key_still_401(client, monkeypatch):
    monkeypatch.setattr(c.settings, "api_key", "correct-key")
    r = client.get("/sync/status", headers={"key": "wrong-key"})
    assert r.status_code == 401
