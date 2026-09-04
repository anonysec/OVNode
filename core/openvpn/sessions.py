# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""OpenVPN session diagnostics and best-effort disconnect helpers.

Session matching is dynamic-IP safe: a session marker is considered live
when its (common_name, pool IP) pair appears in the status file — the pool
IP is stable for the lifetime of a session, unlike the client's real
IP:port, which changes on every reconnect for mobile/dynamic-IP users.
Real-address matching is kept only as a fallback for markers that predate
pool-IP keying.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import socket
import subprocess
import time
from collections import Counter
from typing import Any

from core.logger import logger
from core.openvpn.store import SESSIONS_DIR
from core.validation import _CLIENT_NAME_RE, _SIMPLE_ID_RE, _UUID_RE

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
STATUS_FILE = os.getenv("OVNODE_STATUS_FILE", os.path.join(_OPENVPN_ROOT, "server", "status.log"))
# Canonical host var is OVNODE_MANAGEMENT_HOST; the connect hook
# historically reads OVNODE_MGMT_HOST, so accept both (canonical wins).
_OVPN_MGMT_HOST = (
    os.getenv("OVNODE_MANAGEMENT_HOST") or os.getenv("OVNODE_MGMT_HOST") or "127.0.0.1"
)
MANAGEMENT_HOST = _OVPN_MGMT_HOST


def _parse_mgmt_port(raw: str | None) -> int:
    try:
        port = int((raw or "7505").strip())
    except (ValueError, AttributeError):
        logger.warning("Invalid OVNODE_MANAGEMENT_PORT=%r, falling back to 7505", raw)
        return 7505
    if not 1 <= port <= 65535:
        logger.warning("Out-of-range OVNODE_MANAGEMENT_PORT=%r, falling back to 7505", raw)
        return 7505
    return port


MANAGEMENT_PORT = _parse_mgmt_port(os.getenv("OVNODE_MANAGEMENT_PORT"))

# journalctl is a subprocess fork per call; the panel polls /sync/sessions
# from several jobs, so cache the journal tail briefly to keep CPU flat.
_JOURNAL_TTL = 5.0
_journal_cache: dict[int, tuple[float, list[str]]] = {}
# Tri-state availability probe: None = unchecked, True/False = cached.
# In Docker there is no journald/journalctl at all — without this, every
# cache miss forked a doomed subprocess and logged a warning, spamming the
# container log every few seconds and inflating warnings_1h (feedback loop
# into /sync/status and /sync/logs).
_journal_available: bool | None = None


def _read_status_sessions() -> list[dict[str, Any]]:
    """Read live sessions from the OpenVPN status file."""
    from core.openvpn.status import parse_sessions

    return parse_sessions()


def _read_active_files() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in glob.glob(os.path.join(SESSIONS_DIR, "*")):
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


def _marker_is_live(marker: dict[str, Any], live_sessions: list[dict[str, Any]]) -> bool:
    """True when a marker corresponds to a session in the status file.

    Primary match: (common_name, pool IP) — IP-change proof.
    Fallback (legacy markers without a pool IP): (common_name, real ip:port).
    """
    cn = marker["common_name"]
    pool_ip = marker.get("ifconfig_pool_remote_ip", "")
    if pool_ip:
        return any(
            s["common_name"] == cn and s["virtual_address"] == pool_ip for s in live_sessions
        )
    return any(
        s["common_name"] == cn
        and s["trusted_ip"] == marker.get("trusted_ip", "")
        and s["trusted_port"] == marker.get("trusted_port", "")
        for s in live_sessions
    )


def _journal_lines(hours: int) -> list[str]:
    global _journal_available
    bounded = max(1, min(int(hours or 8), 168))
    now = time.monotonic()
    cached = _journal_cache.get(bounded)
    if cached and now - cached[0] < _JOURNAL_TTL:
        return cached[1]
    if _journal_available is None:
        _journal_available = shutil.which("journalctl") is not None
        if not _journal_available:
            logger.debug("journalctl not available; max-login auth stats disabled")
    if not _journal_available:
        lines: list[str] = []
    else:
        try:
            out = subprocess.check_output(
                [
                    "journalctl",
                    "-t",
                    "ovnode-mlogin",
                    "--since",
                    f"{bounded} hours ago",
                    "--no-pager",
                ],
                text=True,
                errors="ignore",
                timeout=8,
            )
            lines = out.splitlines()
        except Exception as e:
            logger.warning("Failed to read ovnode-mlogin journal: %s", e)
            lines = []
    _journal_cache.clear()
    _journal_cache[bounded] = (now, lines)
    return lines


def user_diagnostics(common_name: str | None = None, hours: int = 8) -> dict[str, Any]:
    """Session diagnostics in the exact shape OVManager consumes.

    Panel consumers of GET /sync/sessions ``data``:

    * ``live_sessions``       — node/diagnostics.py, node/sync.py, mlogin cleanup
    * ``sessions``            — frontend NodeDrawer "Sessions" tab (alias of
                                live_sessions; each row needs common_name,
                                trusted_ip, bytes_received, bytes_sent)
    * ``stale_markers``       — node/sync.py clean_stale_sessions_all_nodes
    * ``live_count`` / ``stale_marker_count`` / ``auth_errors`` / ``rejects``
                              — operations/metrics.py node snapshots
    * ``auth_errors_by_cn``   — node/diagnostics.py login_health_summary,
                                keyed by panel USERNAME (it does
                                ``auth_counts.get(u.name)``), so CNs are
                                mapped to usernames here.
    """
    live = _read_status_sessions()
    active = _read_active_files()
    stale = [a for a in active if not _marker_is_live(a, live)]

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

    # login_health_summary() looks auth counts up by username, so map CNs.
    from core.openvpn.users import display_name_for_cn

    auth_errors_by_cn: dict[str, int] = {}
    for cn, count in auth_errors.items():
        key = display_name_for_cn(cn)
        auth_errors_by_cn[key] = auth_errors_by_cn.get(key, 0) + count

    return {
        "common_name": common_name,
        "live_sessions": live,
        # Alias consumed by the panel frontend (NodeDrawer sessions tab).
        # Copy so callers mutating one list don't affect the other.
        "sessions": list(live),
        "active_markers": active,
        "stale_markers": stale,
        "live_count": len(live),
        "active_marker_count": len(active),
        "stale_marker_count": len(stale),
        "auth_errors": sum(auth_errors.values()),
        "auth_errors_by_cn": auth_errors_by_cn,
        "rejects": sum(rejects.values()),
        "global_rejects": sum(global_rejects.values()),
        "last_error": next(iter(last_errors.values()), None) if cn_filter else last_errors,
        "management_available": _management_available(),
    }


def _mgmt_password() -> str | None:
    """Read the management password (0600 file); None on legacy installs."""
    for path in (
        os.path.join(_OPENVPN_ROOT, "server", "mgmt-pass"),
        os.getenv("OVNODE_MGMT_PASS_FILE", ""),
    ):
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                pw = f.read().strip().splitlines()[0].strip() if f else ""
            if pw:
                return pw
        except OSError:
            continue
    return None


def _mgmt_authenticate(s: socket.socket, banner: str) -> str:
    """Handle ENTER PASSWORD challenge when the daemon requires it.

    Returns the (possibly updated) banner after auth. Legacy passwordless
    daemons skip this entirely.
    """
    if "ENTER PASSWORD" not in banner.upper() and "PASSWORD:" not in banner.upper():
        return banner
    pw = _mgmt_password()
    if not pw:
        return banner
    try:
        s.sendall(f"{pw}\n".encode())
        s.settimeout(2.0)
        try:
            resp = s.recv(4096).decode(errors="ignore")
        except TimeoutError:
            resp = ""
        return banner + "\n" + resp
    except OSError:
        return banner


def _management_available() -> bool:
    try:
        with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), timeout=1.0) as s:
            s.settimeout(1.0)
            banner = s.recv(512).decode(errors="ignore")
            _mgmt_authenticate(s, banner)
            s.sendall(b"quit\n")
        return True
    except Exception:
        return False


def _management_send(command: str) -> dict[str, Any]:
    try:
        with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), timeout=3.0) as s:
            banner = s.recv(1024).decode(errors="ignore")
            banner = _mgmt_authenticate(s, banner)
            s.sendall(f"{command}\n".encode())
            # Read until the daemon terminates its reply (SUCCESS/ERROR line)
            # or a deadline hits — a single 4KB recv can truncate multiline
            # replies and mis-classify the result.
            s.settimeout(1.0)
            deadline = time.monotonic() + 3.0
            chunks = []
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk.decode(errors="ignore"))
                text = "".join(chunks)
                upper = text.upper()
                if "SUCCESS" in upper or "ERROR" in upper:
                    break
            response = "".join(chunks)
            try:
                s.sendall(b"quit\n")
            except OSError:
                pass
        ok = "SUCCESS" in response.upper()
        return {"available": True, "ok": ok, "banner": banner.strip(), "response": response.strip()}
    except Exception as e:
        return {"available": False, "ok": False, "error": str(e)}


def _kill_target_ok(common_name: str) -> bool:
    """Whether a CN is safe to interpolate into a management command.

    Canonical identities are UUIDs (36 chars) or simple IDs (≤64) — both
    wider than the 32-char OpenVPN display-name pattern, which is why UUID
    disconnects were previously rejected after passing route validation.
    The accepted charset stays shell/protocol-safe (alnum plus . _ -).
    """
    return bool(
        _CLIENT_NAME_RE.match(common_name)
        or _UUID_RE.match(common_name)
        or _SIMPLE_ID_RE.match(common_name)
    )


def _management_kill(common_name: str, live_sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """Kill a user's sessions, preferring CID kills (dynamic-IP safe).

    ``client-kill <CID>`` targets the exact session regardless of the
    client's current real address; ``kill <cn>`` is the fallback when the
    status file carries no client id (very old OpenVPN).
    """
    # Validate CN against allowed character set before sending to management socket.
    # Unsanitized CNs could inject shell/protocol commands.
    if not _kill_target_ok(common_name):
        return {"available": True, "ok": False, "error": "invalid cn format"}

    cids = [
        s["client_id"]
        for s in live_sessions
        if s["common_name"] == common_name and s.get("client_id", "").isdigit()
    ]
    if not cids:
        return _management_send(f"kill {common_name}")

    results = [_management_send(f"client-kill {cid}") for cid in cids]
    return {
        "available": any(r.get("available") for r in results),
        "ok": all(r.get("ok") for r in results),
        "killed_cids": cids,
        "responses": [r.get("response") or r.get("error", "") for r in results],
    }


def disconnect_user(common_name: str) -> dict[str, Any]:
    """Best-effort disconnect.

    If OpenVPN management is enabled, kill the live client(s) by CID. Always
    removes stale local active markers for this CN so max-login does not
    stay blocked.
    """
    before = user_diagnostics(common_name=common_name, hours=8)
    live_sessions = _read_status_sessions()
    mgmt = _management_kill(common_name, live_sessions)

    removed_markers = []
    for marker in _read_active_files():
        if marker["common_name"] != common_name:
            continue
        # Remove stale markers immediately. If management succeeded, remove all
        # markers for that CN because the live sessions were killed.
        if mgmt.get("ok") or not _marker_is_live(marker, live_sessions):
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
