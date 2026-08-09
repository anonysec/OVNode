"""Portable test defaults; production paths remain unchanged."""
import os
from pathlib import Path

TEST_OPENVPN_ROOT = Path(__file__).parent / ".test-openvpn"
TEST_OPENVPN_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("API_KEY", "test-api-key-1234567890")
os.environ.setdefault("OVNODE_OPENVPN_ROOT", str(TEST_OPENVPN_ROOT))
os.environ.setdefault("OVNODE_STATUS_FILE", str(TEST_OPENVPN_ROOT / "server" / "status.log"))
