# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

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
import json
import os
import re
import shutil
import socket
import subprocess
import time
from collections import Counter
from typing import Any

from core.logger import logger
from core.openvpn.store import OVNODE_DIR, SESSIONS_DIR
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
_journal_cache: dict[str, tuple[int, float, list[str]]] = {}
# Management liveness is probed on every diagnostics poll — cache briefly.
_MGMT_TTL = 8.0
_mgmt_available_cached: bool | None = None

# A reject is not automatically an authentication failure. The max-login hook
# logs four distinct situations and the panel used to present all of them as
# "auth errors", which made a deliberately disabled user's reconnect look like
# a security incident. Severities: policy = expected, warn = unexplained,
# failure = the node or the TLS layer is actually broken.
_SEVERITY_POLICY = "policy"
_SEVERITY_WARN = "warn"
_SEVERITY_FAILURE = "failure"

_REJECT_REASONS = (
    ("is disabled", "disabled", _SEVERITY_POLICY, "user disabled in the panel"),
    ("disabled;", "disabled", _SEVERITY_POLICY, "user disabled in the panel"),
    ("USERS_DIR missing", "fail_closed", _SEVERITY_FAILURE, "node user state missing"),
    ("could not verify", "takeover_failed", _SEVERITY_FAILURE, "old session not terminated"),
    ("management unavailable", "mgmt_degraded", _SEVERITY_WARN, "management unavailable"),
    ("GLOBAL_CHECK_FAILED", "global_check", _SEVERITY_POLICY, "panel policy check failed"),
    ("GLOBAL_REJECT", "global_policy", _SEVERITY_POLICY, "panel rejected the connection"),
    ("max login reached", "max_logins", _SEVERITY_POLICY, "max logins reached"),
)
_TLS_ERROR_RE = re.compile(
    r"(TLS Error|Auth Failed|VERIFY ERROR|CRL has expired|certificate revoked|SSL error)",
    re.IGNORECASE,
)
# Some builds DO stamp the log ("Fri Sep 25 01:23:45 2026 TLS Error: ...").
# Ours do not (log-append + --suppress-timestamps), so the prefix is optional
# and the observed first/last-seen times are used instead.
_OPENVPN_TS_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(.*)$"
)
_PEER_RE = re.compile(r"\[AF_INET6?\](\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|\S+:\d+)")
# Agent-owned state (per-failure first/last-seen times) lives beside the
# per-user and per-session trees, not in the user's data dir.
_STATE_DIR = os.path.join(OVNODE_DIR, "state")

_mgmt_available_at = 0.0
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


def _live_index(live_sessions: list[dict[str, Any]]) -> tuple[set, set]:
    """O(1) lookup sets for marker matching: {(cn, pool)} + {(cn, ip, port)}."""
    pool = {(s.get("common_name"), s.get("virtual_address") or "") for s in live_sessions}
    real = {
        (s.get("common_name"), s.get("trusted_ip") or "", s.get("trusted_port") or "")
        for s in live_sessions
    }
    return pool, real


def _marker_is_live(
    marker: dict[str, Any],
    live_sessions: list[dict[str, Any]],
    _index: tuple[set, set] | None = None,
) -> bool:
    """True when a marker corresponds to a session in the status file.

    Primary match: (common_name, pool IP) — IP-change proof.
    Fallback (legacy markers without a pool IP): (common_name, real ip:port).
    Pass a prebuilt `_live_index()` when checking many markers.
    """
    cn = marker["common_name"]
    pool_ip = marker.get("ifconfig_pool_remote_ip", "")
    if pool_ip:
        if _index is not None:
            return (cn, pool_ip) in _index[0]
        return any(
            s["common_name"] == cn and s["virtual_address"] == pool_ip for s in live_sessions
        )
    if _index is not None:
        return (
            cn,
            marker.get("trusted_ip", ""),
            marker.get("trusted_port", ""),
        ) in _index[1]
    return any(
        s["common_name"] == cn
        and s["trusted_ip"] == marker.get("trusted_ip", "")
        and s["trusted_port"] == marker.get("trusted_port", "")
        for s in live_sessions
    )


def _journal_lines(hours: int) -> list[str]:
    global _journal_available
    # Clamped: a client-controlled `hours` up to 168 used to fork a 7-day
    # journal scan, and alternating values defeated the TTL cache.
    bounded = max(1, min(int(hours or 8), 24))
    now = time.monotonic()
    cached = _journal_cache.get("last")
    if cached and cached[0] == bounded and now - cached[1] < _JOURNAL_TTL:
        return cached[2]
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
                    # Epoch prefix: the panel showed a guessed year/time parsed
                    # back out of the human-readable stamp, which was wrong for
                    # any event near a new year. short-unix gives a real ts.
                    "-o",
                    "short-unix",
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
    _journal_cache["last"] = (bounded, now, lines)
    return lines


def _split_journal_line(line: str) -> tuple[float, str]:
    """Return (epoch, message) for a `journalctl -o short-unix` line.

    Falls back to (0, line) for any other format so a pre-existing/legacy
    journal source can never crash or silently drop its events.
    """
    head, _, rest = line.partition(" ")
    try:
        return float(head), rest
    except ValueError:
        return 0.0, line


def _classify_reject(message: str) -> tuple[str, str, str]:
    """Map a max-login hook line to (action, severity, human reason)."""
    for needle, action, severity, reason in _REJECT_REASONS:
        if needle in message:
            return action, severity, reason
    # The strict max-login hook line carries the limit, not the words
    # "max login reached": "CN=1 ... limit=2 active=2 status=2; REJECT".
    if "REJECT" in message and re.search(r"\blimit=", message):
        return "max_logins", _SEVERITY_POLICY, "max logins reached"
    if "REJECT" in message:
        # Unexplained reject: shown, but never counted as a security failure.
        return "other", _SEVERITY_WARN, "unclassified reject"
    if "FAILED" in message:
        return "check_failed", _SEVERITY_WARN, "policy check failed"
    return "event", _SEVERITY_POLICY, "session event"


def _openvpn_log_lines() -> list[str]:
    """Tail of the OpenVPN log (the only place its output lands)."""
    path = os.path.join(_OPENVPN_ROOT, "server", "openvpn.log")
    try:
        size = os.path.getsize(path)
        with open(path, encoding="utf-8", errors="ignore") as f:
            # Tail only: the log is append-only and unbounded, and the panel
            # polls this on a timer.
            f.seek(max(0, size - 256 * 1024))
            if size > 256 * 1024:
                f.readline()  # drop the partial first line
            return f.read().splitlines()
    except OSError:
        return []


def _tls_seen_path() -> str:
    return os.path.join(_STATE_DIR, "tls_seen.json")


def _load_tls_seen() -> dict[str, dict[str, float]]:
    try:
        with open(_tls_seen_path(), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except (OSError, ValueError):
        pass
    return {}


def _save_tls_seen(seen: dict[str, dict[str, float]]) -> None:
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = _tls_seen_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(seen, f)
        os.replace(tmp, _tls_seen_path())
        os.chmod(_tls_seen_path(), 0o600)
    except OSError as e:
        logger.debug("could not persist TLS seen-state: %s", e)


def _openvpn_log_events(hours: int) -> list[dict[str, Any]]:
    """Real TLS/auth failures from the OpenVPN log (the danger bucket).

    The max-login journal never sees these: a bad certificate or a failed
    handshake never reaches client-connect, so nothing else in the node can
    report them.

    The log carries no timestamps: OpenVPN writes through `log-append`, so its
    output never reaches the journal, and the distribution unit starts it with
    --suppress-timestamps. There is no option to stamp the file (verified
    against OpenVPN 2.7: `log-timestamp` is not a directive and refuses to
    start). So the times here are the ones *this agent observed* — first seen
    and last seen per distinct failure, kept in a small state file. Honest, and
    identical under systemd, Docker or a bare daemon.
    """
    now = time.time()
    window = max(1, min(int(hours or 8), 24)) * 3600
    fingerprints: dict[str, dict[str, Any]] = {}
    for line in _openvpn_log_lines():
        if not _TLS_ERROR_RE.search(line):
            continue
        peer = _PEER_RE.search(line)
        peer_text = peer.group(1) if peer else "?"
        # Peer + kind is the identity that matters: one scanner retrying is one
        # problem, not N log lines.
        key = f"{peer_text}|{'auth' if 'Auth Failed' in line else 'tls'}"
        detail = line.split(": ", 1)[-1][:160] or line[:160]
        stamped = _OPENVPN_TS_RE.match(line)
        line_ts = 0.0
        if stamped:
            from datetime import datetime

            try:
                line_ts = datetime.strptime(
                    f"{stamped.group(4)} {stamped.group(1)} {stamped.group(2)} {stamped.group(3)}",
                    "%Y %b %d %H:%M:%S",
                ).astimezone().timestamp()
            except ValueError:
                line_ts = 0.0
            # A stamped line can be aged out exactly. An unstamped one cannot:
            # it is in the log right now, and first/last-seen is all we know.
            if line_ts and now - line_ts > window:
                continue
        entry = fingerprints.get(key)
        if entry is None:
            fingerprints[key] = {
                "count": 1,
                # A stamped build gives the exact time; otherwise the time this
                # agent first observed the failure.
                "first": line_ts or now,
                "last": line_ts or now,
                "peer": peer_text,
                "reason": detail,
            }
        else:
            entry["count"] += 1
            if line_ts:
                entry["last"] = max(entry["last"], line_ts)
                entry["first"] = min(entry["first"], line_ts) if entry["first"] else line_ts
            else:
                entry["last"] = now
    if not fingerprints:
        # Nothing in the log: forget what we saw, so a failure that stopped
        # does not stay "ongoing" forever.
        _save_tls_seen({})
        return []

    seen = _load_tls_seen()
    events: list[dict[str, Any]] = []
    for key, entry in fingerprints.items():
        prior = seen.get(key) or {}
        # A stamped line is authoritative; otherwise keep the first time this
        # agent saw this failure so the panel can show a stable "since".
        first = entry["first"] or float(prior.get("first") or 0) or now
        last = max(entry["last"], float(prior.get("last") or 0))
        # Present in this poll AND in the previous one: still happening.
        ongoing = bool(prior) and (now - float(prior.get("last") or 0)) <= window / 2
        events.append(
            {
                "ts": first,
                "last_seen": last,
                "ongoing": ongoing,
                "count": entry["count"],
                "cn": "",
                "action": "tls_auth" if key.endswith("|auth") else "tls",
                "severity": _SEVERITY_FAILURE,
                "reason": entry["reason"],
                "peer": entry["peer"],
                "source": "openvpn",
            }
        )
    # Bounded by construction: whatever is not in this poll is forgotten.
    _save_tls_seen(
        {
            key: {"first": entry["first"], "last": entry["last"]}
            for key, entry in fingerprints.items()
        }
    )
    events.sort(key=lambda e: e["ts"], reverse=True)
    return events


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
    * ``events``              — structured, classified events (ts, cn, action,
                                severity, reason, peer) for the panel's
                                Security view. ``severity`` is policy / warn /
                                failure; only ``failure`` counts as a real
                                authentication or TLS problem.
    """
    live = _read_status_sessions()
    active = _read_active_files()
    index = _live_index(live)
    stale = [a for a in active if not _marker_is_live(a, live, index)]

    cn_filter = common_name or None
    if cn_filter:
        live = [s for s in live if s["common_name"] == cn_filter]
        active = [a for a in active if a["common_name"] == cn_filter]
        stale = [a for a in stale if a["common_name"] == cn_filter]

    rejects = Counter()
    global_rejects = Counter()
    auth_errors = Counter()
    rejects_by_reason: Counter = Counter()
    last_errors: dict[str, str] = {}
    last_event_ts: dict[str, float] = {}
    events: list[dict[str, Any]] = []
    for line in _journal_lines(hours):
        ts, message = _split_journal_line(line)
        m = re.search(
            r"CN=([^ ]+).*?(GLOBAL_REJECT|LOCAL_REJECT|REJECT|GLOBAL_CHECK_FAILED)", message
        )
        if not m:
            continue
        cn, hook_action = m.group(1), m.group(2)
        if cn_filter and cn != cn_filter:
            continue
        action, severity, reason = _classify_reject(message)
        rejects[cn] += 1
        rejects_by_reason[reason] += 1
        if hook_action == "GLOBAL_REJECT":
            global_rejects[cn] += 1
        if severity == _SEVERITY_FAILURE:
            auth_errors[cn] += 1
        last_errors[cn] = message
        last_event_ts[cn] = max(ts, last_event_ts.get(cn, 0.0))
        events.append(
            {
                "ts": ts,
                "last_seen": ts,
                # The hook knows nothing beyond this line, so the panel decides
                # "ongoing" from the timestamp.
                "ongoing": None,
                "cn": cn,
                "action": action,
                "severity": severity,
                "reason": reason,
                "peer": "",
                "source": "mlogin",
            }
        )

    # TLS/auth failures never reach the max-login hook, so they come from the
    # OpenVPN log and are the only events that justify a danger badge.
    tls_total = 0
    for ev in _openvpn_log_events(hours):
        if cn_filter:
            continue
        rejects_by_reason[ev["reason"]] += 1
        auth_errors[""] += 1
        tls_total += 1
        events.append(ev)

    events.sort(key=lambda e: float(e.get("ts") or 0), reverse=True)
    policy_total = sum(1 for e in events if e.get("severity") == _SEVERITY_POLICY)
    warn_total = sum(1 for e in events if e.get("severity") == _SEVERITY_WARN)
    failure_total = sum(1 for e in events if e.get("severity") == _SEVERITY_FAILURE)

    # login_health_summary() looks auth counts up by username, so map CNs.
    from core.openvpn.users import display_name_for_cn

    auth_errors_by_cn: dict[str, int] = {}
    for cn, count in auth_errors.items():
        key = display_name_for_cn(cn) if cn else "(tls)"
        auth_errors_by_cn[key] = auth_errors_by_cn.get(key, 0) + count
    rejects_by_cn: dict[str, int] = {}
    for cn, count in rejects.items():
        key = display_name_for_cn(cn)
        rejects_by_cn[key] = rejects_by_cn.get(key, 0) + count

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
        # Real authentication/TLS failures only — a disabled user's reconnect
        # is a policy reject and must not raise this counter.
        "auth_errors": failure_total,
        "auth_errors_by_cn": auth_errors_by_cn,
        # Every event the panel can show: policy + warn + failure.
        "total_events": policy_total + warn_total + failure_total,
        "policy_rejects": policy_total,
        "warn_rejects": warn_total,
        "failures": failure_total,
        "tls_failures": tls_total,
        "rejects": sum(rejects.values()),
        "rejects_by_reason": dict(rejects_by_reason),
        "rejects_by_cn": rejects_by_cn,
        "last_event_ts": last_event_ts,
        "events": events[:100],
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
                lines = f.read().strip().splitlines()
            pw = lines[0].strip() if lines else ""
            if pw:
                return pw
        except OSError:
            continue
    return None


_mgmt_passwordless_warned = False


def _mgmt_authenticate(s: socket.socket, banner: str) -> str:
    """Handle ENTER PASSWORD challenge when the daemon requires it.

    Returns the (possibly updated) banner after auth. Legacy passwordless
    daemons skip this entirely — but that means any local process can drive
    the management socket, so warn loudly (once) instead of staying silent.
    """
    global _mgmt_passwordless_warned
    if "ENTER PASSWORD" not in banner.upper() and "PASSWORD:" not in banner.upper():
        if not _mgmt_passwordless_warned:
            _mgmt_passwordless_warned = True
            logger.warning(
                "Management socket has NO password (legacy install) — any local "
                "process can kill VPN sessions. Restart the agent to upgrade to "
                "password-protected management."
            )
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
    """Cached liveness probe: user_diagnostics() calls this on every poll,
    so a fresh TCP handshake per call would be constant churn."""
    global _mgmt_available_cached, _mgmt_available_at
    now = time.monotonic()
    if _mgmt_available_cached is not None and now - _mgmt_available_at < _MGMT_TTL:
        return _mgmt_available_cached
    try:
        with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), timeout=1.0) as s:
            s.settimeout(1.0)
            banner = s.recv(512).decode(errors="ignore")
            _mgmt_authenticate(s, banner)
            s.sendall(b"quit\n")
        result = True
    except Exception:
        result = False
    _mgmt_available_cached = result
    _mgmt_available_at = now
    return result


def _read_mgmt_reply(s: socket.socket, deadline: float) -> str:
    """Read one management reply (up to SUCCESS/ERROR) or the deadline."""
    s.settimeout(1.0)
    chunks = []
    while time.monotonic() < deadline:
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk.decode(errors="ignore"))
        upper = "".join(chunks).upper()
        if "SUCCESS" in upper or "ERROR" in upper:
            break
    return "".join(chunks)


def _management_send_many(commands: list[str]) -> list[dict[str, Any]]:
    """Run several commands over ONE management connection.

    A mass-kick previously paid a TCP handshake + banner + auth per CID;
    pipelining keeps it to one. Results align with `commands`.
    """
    if not commands:
        return []
    try:
        with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), timeout=3.0) as s:
            banner = s.recv(1024).decode(errors="ignore")
            banner = _mgmt_authenticate(s, banner)
            out = []
            for command in commands:
                try:
                    s.sendall(f"{command}\n".encode())
                    response = _read_mgmt_reply(s, time.monotonic() + 3.0).strip()
                    out.append(
                        {
                            "available": True,
                            "ok": "SUCCESS" in response.upper(),
                            "banner": banner.strip(),
                            "response": response,
                        }
                    )
                except Exception as e:
                    out.append({"available": True, "ok": False, "error": str(e)})
            try:
                s.sendall(b"quit\n")
            except OSError:
                pass
            return out
    except Exception as e:
        return [{"available": False, "ok": False, "error": str(e)} for _ in commands]


def _management_send(command: str) -> dict[str, Any]:
    """Single management command (kept for the `kill <cn>` fallback path)."""
    return _management_send_many([command])[0]


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

    # One connection for the whole batch (was: a handshake per CID).
    results = _management_send_many([f"client-kill {cid}" for cid in cids])
    return {
        "available": any(r.get("available") for r in results),
        "ok": all(r.get("ok") for r in results),
        "killed_cids": cids,
        "responses": [r.get("response") or r.get("error", "") for r in results],
    }


def disconnect_user(common_name: str, only_stale: bool = False) -> dict[str, Any]:
    """Best-effort disconnect.

    If OpenVPN management is enabled, kill the live client(s) by CID. Always
    removes stale local active markers for this CN so max-login does not
    stay blocked.

    With ``only_stale=True`` no kill is attempted and only markers with no
    live counterpart are removed: safe for CNs that also hold a healthy
    session, where a dead marker previously meant "full" forever (neither
    the hook sweep nor the panel sweeper would clear it).
    """
    before = user_diagnostics(common_name=common_name, hours=8)
    live_sessions = _read_status_sessions()
    if only_stale:
        mgmt = {"available": None, "ok": None, "skipped": "only_stale"}
    else:
        mgmt = _management_kill(common_name, live_sessions)

    index = _live_index(live_sessions)
    removed_markers = []
    for marker in _read_active_files():
        if marker["common_name"] != common_name:
            continue
        # Remove stale markers immediately. If management succeeded, remove all
        # markers for that CN because the live sessions were killed.
        if mgmt.get("ok") or not _marker_is_live(marker, live_sessions, index):
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
