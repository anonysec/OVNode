# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Portable test defaults; production paths remain unchanged."""

# anyio 4.15 moved BlockingPortal to anyio.from_thread and emits a
# DeprecationWarning on the old anyio.abc alias — which starlette's
# TestClient still reads at import (annotations evaluated eagerly). Both
# packages are at latest; pre-binding the new location keeps the suite
# warning-free until starlette catches up.
import anyio.abc
import anyio.from_thread

if "BlockingPortal" not in anyio.abc.__dict__:
    anyio.abc.BlockingPortal = anyio.from_thread.BlockingPortal  # type: ignore[attr-defined]

import os
from pathlib import Path

TEST_OPENVPN_ROOT = Path(__file__).parent / ".test-openvpn"
TEST_OPENVPN_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("API_KEY", "test-api-key-1234567890")
os.environ.setdefault("OVNODE_OPENVPN_ROOT", str(TEST_OPENVPN_ROOT))
os.environ.setdefault("OVNODE_STATUS_FILE", str(TEST_OPENVPN_ROOT / "server" / "status.log"))
