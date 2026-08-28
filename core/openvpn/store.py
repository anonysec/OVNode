# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""On-disk state store — the single owner of the ``ovnode/`` tree.

Everything OVNode knows about users and sessions lives under ONE directory,
so a node backup/export is exactly two paths: this tree + the PKI.

    <OVNODE_OPENVPN_ROOT>/ovnode/
    ├── users/<cn>/          one folder per user — the whole user
    │   ├── name             panel username (display / usage keying)
    │   ├── limit            max simultaneous logins (0 = unlimited)
    │   ├── disabled         marker file — exists = connections rejected
    │   └── client.ovpn      cached generated profile (disposable)
    ├── sessions/            live-session markers written by the hooks
    │   └── .lock
    └── scripts/             installed connect/disconnect hooks

Plain files, one value each: the bash enforcement hooks read ``limit`` and
``disabled`` directly with no parser, and admins can inspect or fix a user
with ``ls``. Legacy layouts (clients/, limits/, disabled/, ovnode-active/,
uid_map.json) are migrated automatically by :func:`ensure_layout`, so
restoring an old node backup onto a current build just works.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time

from core.logger import logger

# A store key is any valid user identity: a client name (<=32 chars, dots
# allowed) or a panel user id (UUID / simple id, <=64 chars). Path-safe by
# construction — no separators, no traversal.
_STORE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")

OVNODE_DIR = os.path.join(_OPENVPN_ROOT, "ovnode")
USERS_DIR = os.path.join(OVNODE_DIR, "users")
SESSIONS_DIR = os.path.join(OVNODE_DIR, "sessions")
SCRIPTS_DIR = os.path.join(OVNODE_DIR, "scripts")
# Cumulative per-user byte counters, written by the disconnect hook when a
# session ends (its final bytes_received/bytes_sent). Lives outside users/
# because the hook runs as the OpenVPN runtime user, which must be able to
# write here but must NOT be able to touch limits/disabled markers.
USAGE_DIR = os.path.join(OVNODE_DIR, "usage")
LOCK_FILE = os.path.join(SESSIONS_DIR, ".lock")

# cn → username map cache for the usage/sessions hot path (the panel polls
# every few seconds). Invalidated by every in-process write; the short TTL
# covers out-of-band edits.
_NAME_CACHE_TTL = 5.0
_name_cache: tuple[float, dict[str, str]] | None = None


# ── paths ────────────────────────────────────────────────────────────


def _safe_cn(cn: str) -> str:
    """Validate a CN before it becomes a path component (defense in depth)."""
    cn = str(cn).strip()
    if not _STORE_KEY_RE.match(cn):
        raise ValueError(f"invalid common name: {cn!r}")
    return cn


def user_dir(cn: str) -> str:
    return os.path.join(USERS_DIR, _safe_cn(cn))


def ovpn_path(cn: str) -> str:
    return os.path.join(user_dir(cn), "client.ovpn")


def _attr_path(cn: str, attr: str) -> str:
    return os.path.join(user_dir(cn), attr)


# ── user attributes ──────────────────────────────────────────────────


def user_exists(cn: str) -> bool:
    return os.path.isdir(user_dir(cn))


def list_users() -> list[str]:
    try:
        return sorted(e for e in os.listdir(USERS_DIR) if _STORE_KEY_RE.match(e))
    except OSError:
        return []


def create_user(cn: str) -> None:
    """Create the user directory (idempotent). Hooks only need to traverse."""
    os.makedirs(user_dir(cn), exist_ok=True)
    os.chmod(user_dir(cn), 0o755)


def delete_user(cn: str) -> None:
    """Remove the whole user folder — name, limit, markers, cached profile."""
    _invalidate_name_cache()
    shutil.rmtree(user_dir(cn), ignore_errors=True)
    reset_usage(cn)


def _read(cn: str, attr: str) -> str | None:
    try:
        with open(_attr_path(cn, attr), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def _write(cn: str, attr: str, value: str, mode: int = 0o644) -> None:
    create_user(cn)
    path = _attr_path(cn, attr)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{value}\n")
    os.chmod(path, mode)


def get_name(cn: str) -> str | None:
    return _read(cn, "name")


def set_name(cn: str, name: str) -> None:
    _invalidate_name_cache()
    # Username is panel data, not needed by the hooks — keep it root-only.
    _write(cn, "name", name, mode=0o600)


def get_limit(cn: str) -> int | None:
    raw = _read(cn, "limit")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def set_limit(cn: str, max_logins: int) -> None:
    # Read by the connect hook (as the OpenVPN runtime user) → world-readable.
    _write(cn, "limit", str(max(0, int(max_logins))))


def is_disabled(cn: str) -> bool:
    return os.path.exists(_attr_path(cn, "disabled"))


def set_disabled(cn: str, disabled: bool) -> None:
    if disabled:
        _write(cn, "disabled", "disabled")
    else:
        try:
            os.remove(_attr_path(cn, "disabled"))
        except FileNotFoundError:
            pass


# ── username lookups ─────────────────────────────────────────────────


def _invalidate_name_cache() -> None:
    global _name_cache
    _name_cache = None


def name_map() -> dict[str, str]:
    """cn → username for every user that has one (cached)."""
    global _name_cache
    now = time.monotonic()
    if _name_cache and now - _name_cache[0] < _NAME_CACHE_TTL:
        return _name_cache[1]
    mapping: dict[str, str] = {}
    for cn in list_users():
        name = get_name(cn)
        if name:
            mapping[cn] = name
    _name_cache = (now, mapping)
    return mapping


def cn_for_name(name: str) -> str | None:
    """Reverse lookup: panel username → CN (None when unknown)."""
    for cn, uname in name_map().items():
        if uname == name:
            return cn
    return None


# ── usage accounting ─────────────────────────────────────────────────


def accumulated_usage(cn: str) -> int:
    """Total bytes from this user's COMPLETED sessions (0 when none)."""
    try:
        with open(os.path.join(USAGE_DIR, _safe_cn(cn)), encoding="utf-8") as f:
            raw = f.read().strip()
        return int(raw) if raw.isdigit() else 0
    except OSError:
        return 0


def all_accumulated_usage() -> dict[str, int]:
    """cn → completed-session bytes for every user with recorded usage."""
    usage: dict[str, int] = {}
    try:
        entries = os.listdir(USAGE_DIR)
    except OSError:
        return usage
    for entry in entries:
        if _STORE_KEY_RE.match(entry):
            value = accumulated_usage(entry)
            if value:
                usage[entry] = value
    return usage


def reset_usage(cn: str) -> None:
    try:
        os.remove(os.path.join(USAGE_DIR, _safe_cn(cn)))
    except FileNotFoundError:
        pass


# ── layout / migration ───────────────────────────────────────────────


def ensure_layout() -> None:
    """Create the ovnode tree and absorb any legacy layout. Idempotent."""
    for d in (OVNODE_DIR, USERS_DIR, SESSIONS_DIR, SCRIPTS_DIR, USAGE_DIR):
        os.makedirs(d, exist_ok=True)
    _migrate_legacy()


def _migrate_legacy() -> None:
    """Move pre-store state into the ovnode tree.

    Old layout: clients/<cn>.ovpn + clients/uid_map.json, limits/<cn>,
    disabled/<cn>, ovnode-active/<marker>, scripts/ovnode-client-*.sh —
    six scattered directories. Files are MOVED (never copied) and existing
    new-layout files are never overwritten, so the migration is safe to
    re-run and works on restored old backups.
    """
    moved = 0
    legacy_clients = os.path.join(_OPENVPN_ROOT, "clients")
    legacy_limits = os.path.join(_OPENVPN_ROOT, "limits")
    legacy_disabled = os.path.join(_OPENVPN_ROOT, "disabled")
    legacy_active = os.path.join(_OPENVPN_ROOT, "ovnode-active")
    legacy_scripts = os.path.join(_OPENVPN_ROOT, "scripts")

    # uid_map.json {uid: username} → users/<uid>/name
    uid_map = os.path.join(legacy_clients, "uid_map.json")
    if os.path.isfile(uid_map):
        try:
            with open(uid_map, encoding="utf-8") as f:
                for uid, name in (json.load(f) or {}).items():
                    if _STORE_KEY_RE.match(str(uid)) and get_name(uid) is None:
                        set_name(str(uid), str(name))
                        moved += 1
            os.remove(uid_map)
        except Exception as e:
            logger.error("store: uid_map migration failed: %s", e)

    moved += _move_dir(legacy_clients, lambda cn: ovpn_path(cn), suffix=".ovpn")
    moved += _move_dir(legacy_limits, lambda cn: _attr_path(cn, "limit"))
    moved += _move_dir(legacy_disabled, lambda cn: _attr_path(cn, "disabled"))

    # Session markers move verbatim (same filename scheme, new home).
    if os.path.isdir(legacy_active):
        for entry in os.listdir(legacy_active):
            src = os.path.join(legacy_active, entry)
            dst = os.path.join(SESSIONS_DIR, entry)
            if os.path.isfile(src) and not os.path.exists(dst):
                shutil.move(src, dst)
                moved += 1
        _rmdir_if_empty(legacy_active)

    # Old hook copies are stale (server.conf is repointed by multilogin).
    for fname in ("ovnode-client-connect.sh", "ovnode-client-disconnect.sh", "ovnode-mlogin.env"):
        try:
            os.remove(os.path.join(legacy_scripts, fname))
            moved += 1
        except OSError:
            pass
    _rmdir_if_empty(legacy_scripts)

    if moved:
        _invalidate_name_cache()
        logger.info("store: migrated %d item(s) from the legacy layout", moved)


def _move_dir(src_dir: str, dst_for_cn, suffix: str = "") -> int:
    """Move <src_dir>/<cn><suffix> files to their per-user destination."""
    if not os.path.isdir(src_dir):
        return 0
    moved = 0
    for entry in os.listdir(src_dir):
        if suffix and not entry.endswith(suffix):
            continue
        cn = entry[: -len(suffix)] if suffix else entry
        if not _STORE_KEY_RE.match(cn):
            continue
        src = os.path.join(src_dir, entry)
        if not os.path.isfile(src):
            continue
        try:
            dst = dst_for_cn(cn)
            if not os.path.exists(dst):
                create_user(cn)
                shutil.move(src, dst)
                moved += 1
            else:
                os.remove(src)
        except Exception as e:
            logger.warning("store: could not migrate %s: %s", src, e)
    _rmdir_if_empty(src_dir)
    return moved


def _rmdir_if_empty(path: str) -> None:
    try:
        os.rmdir(path)
    except OSError:
        pass


# ── runtime permissions ──────────────────────────────────────────────


def runtime_user_group() -> tuple[str, str]:
    """User/group OpenVPN drops privileges to (from server.conf).

    The enforcement hooks run as this user, not root — it must be able to
    read user attributes and write session markers.
    """
    user, group = "nobody", "nogroup"
    server_conf = os.path.join(_OPENVPN_ROOT, "server", "server.conf")
    try:
        if os.path.exists(server_conf):
            with open(server_conf, encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == "user":
                        user = parts[1]
                    elif len(parts) >= 2 and parts[0] == "group":
                        group = parts[1]
    except Exception as e:
        logger.warning("store: failed to read OpenVPN runtime user/group: %s", e)
    return user, group


def fix_runtime_permissions() -> None:
    """Grant the hook runtime user access to the store. Idempotent.

    Without this OpenVPN returns AUTH_FAILED for every client, because the
    connect hook cannot read limits or write its session marker.
    """
    ensure_layout()
    try:
        open(LOCK_FILE, "a").close()
    except OSError:
        pass

    user, group = runtime_user_group()
    try:
        shutil.chown(SESSIONS_DIR, user=user, group=group)
        shutil.chown(USAGE_DIR, user=user, group=group)
        shutil.chown(LOCK_FILE, user=user, group=group)
    except Exception as e:
        logger.warning("store: failed to chown session registry to %s:%s: %s", user, group, e)
    try:
        os.chmod(SESSIONS_DIR, 0o755)
        os.chmod(USAGE_DIR, 0o755)
        os.chmod(USERS_DIR, 0o755)
        os.chmod(LOCK_FILE, 0o664)
    except Exception as e:
        logger.warning("store: failed to chmod store dirs: %s", e)
