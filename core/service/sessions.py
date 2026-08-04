"""OpenVPN session diagnostics and best-effort disconnect helpers."""

from __future__ import annotations

import glob
import os
import re
import socket
import subprocess
from collections import Counter
from typing import Any

from core.logger import logger
from core.validation import _CLIENT_NAME_RE

STATUS_FILE = "/var/log/openvpn-status.log"
ACTIVE_DIR = "/etc/openvpn/ovnode-active"
MANAGEMENT_HOST = os.getenv("OVNODE_MANAGEMENT_HOST", "127.0.0.1")
MANAGEMENT_PORT = int(os.getenv("OVNODE_MANAGEMENT_PORT", "7505"))


def _split_real_address(real_address: str) -> tuple[str, str]:
    if not real_address:
        return "", ""
    if ":" in real_address:
        ip, port = real_address.rsplit(":", 1)
        return ip.strip("[]"), port
    return real_address, ""


def _read_status_sessions() -> list[dict[str, Any]]:
    """Read live sessions from the OpenVPN status file."""
    from core.service.status_parser import parse_sessions
    return parse_sessions()


def _read_active_files() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in glob.glob(os.path.join(ACTIVE_DIR, "*")):
        base = os.path.basename(path)
        if base == ".lock" or not os.path.isfile(path):
            continue
        data: dict[str, str] = {}
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.rstrip("\n").split("=", 1)
                        data[k] = v
            stat = os.stat(path)
            rows.append(
                {
                    "session_key": base,
                    "path": path,
                    "common_name": data.get("common_name", ""),
                    "trusted_ip": data.get("trusted_ip", ""),
                    "trusted_port": data.get("trusted_port", ""),
                    "ifconfig_pool_remote_ip": data.get("ifconfig_pool_remote_ip", ""),
                    "created": int(data.get("created") or 0),
                    "mtime": int(stat.st_mtime),
                }
            )
        except Exception as e:
            logger.warning("Failed to read active marker %s: %s", path, e)
    return rows


def _journal_lines(hours: int) -> list[str]:
    since = f"{max(1, min(int(hours or 8), 168))} hours ago"
    try:
        out = subprocess.check_output(
            ["journalctl", "-t", "ovnode-mlogin", "--since", since, "--no-pager"],
            text=True,
            errors="ignore",
            timeout=8,
        )
        return out.splitlines()
    except Exception as e:
        logger.warning("Failed to read ovnode-mlogin journal: %s", e)
        return []


def user_diagnostics(common_name: str | None = None, hours: int = 8) -> dict[str, Any]:
    live = _read_status_sessions()
    active = _read_active_files()
    live_keys = {(s["common_name"], s["trusted_ip"], s["trusted_port"]) for s in live}
    stale = [
        a for a in active if (a["common_name"], a["trusted_ip"], a["trusted_port"]) not in live_keys
    ]

    cn_filter = common_name or None
    if cn_filter:
        live = [s for s in live if s["common_name"] == cn_filter]
        active = [a for a in active if a["common_name"] == cn_filter]
        stale = [a for a in stale if a["common_name"] == cn_filter]

    rejects = Counter()
    global_rejects = Counter()
    auth_errors = Counter()
    last_errors: dict[str, str] = {}
    for line in _journal_lines(hours):
        m = re.search(r"CN=([^ ]+).*?(GLOBAL_REJECT|LOCAL_REJECT|REJECT|GLOBAL_CHECK_FAILED)", line)
        if not m:
            continue
        cn, action = m.group(1), m.group(2)
        if cn_filter and cn != cn_filter:
            continue
        rejects[cn] += 1
        if action == "GLOBAL_REJECT":
            global_rejects[cn] += 1
        auth_errors[cn] += 1
        last_errors[cn] = line

    return {
        "common_name": common_name,
        "live_sessions": live,
        "active_markers": active,
        "stale_markers": stale,
        "live_count": len(live),
        "active_marker_count": len(active),
        "stale_marker_count": len(stale),
        "auth_errors": sum(auth_errors.values()),
        "rejects": sum(rejects.values()),
        "global_rejects": sum(global_rejects.values()),
        "last_error": next(iter(last_errors.values()), None) if cn_filter else last_errors,
        "management_available": _management_available(),
    }


def _management_available() -> bool:
    try:
        with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), timeout=1.0) as s:
            s.settimeout(1.0)
            s.recv(512)
            s.sendall(b"quit\n")
        return True
    except Exception:
        return False


def _management_kill(common_name: str) -> dict[str, Any]:
    # Validate CN against allowed character set before sending to management socket.
    # Unsanitized CNs could inject shell/protocol commands.
    if not _CLIENT_NAME_RE.match(common_name):
        return {"available": True, "ok": False, "error": "invalid cn format"}
    try:
        with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), timeout=3.0) as s:
            banner = s.recv(1024).decode(errors="ignore")
            s.sendall(f"kill {common_name}\n".encode())
            response = s.recv(4096).decode(errors="ignore")
            s.sendall(b"quit\n")
        ok = "SUCCESS" in response.upper()
        return {"available": True, "ok": ok, "banner": banner.strip(), "response": response.strip()}
    except Exception as e:
        return {"available": False, "ok": False, "error": str(e)}


def disconnect_user(common_name: str) -> dict[str, Any]:
    """Best-effort disconnect.

    If OpenVPN management is enabled, kill the live client(s). Always removes
    stale local active markers for this CN so max-login does not stay blocked.
    """
    before = user_diagnostics(common_name=common_name, hours=8)
    mgmt = _management_kill(common_name)

    removed_markers = []
    live_keys = {
        (s["common_name"], s["trusted_ip"], s["trusted_port"]) for s in _read_status_sessions()
    }
    for marker in _read_active_files():
        if marker["common_name"] != common_name:
            continue
        # Remove stale markers immediately. If management succeeded, remove all
        # markers for that CN because the live sessions were killed.
        is_live = (marker["common_name"], marker["trusted_ip"], marker["trusted_port"]) in live_keys
        if mgmt.get("ok") or not is_live:
            try:
                os.remove(marker["path"])
                removed_markers.append(marker["session_key"])
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning("Failed to remove marker %s: %s", marker["path"], e)

    after = user_diagnostics(common_name=common_name, hours=8)
    return {
        "common_name": common_name,
        "management": mgmt,
        "removed_markers": removed_markers,
        "before": before,
        "after": after,
    }
