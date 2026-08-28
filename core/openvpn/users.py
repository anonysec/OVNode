# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

import json
import os
import subprocess

from core.logger import logger as logger
from core.openvpn.easyrsa import run_easyrsa as _easyrsa
from core.openvpn.pki import PKI_DIR, tls_crypt_block
from core.validation import DeleteResult

# Get the node-specific logger

# Where per-client simultaneous-login limits are stored.
_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
LIMITS_DIR = os.path.join(_OPENVPN_ROOT, "limits")
DISABLED_DIR = os.path.join(_OPENVPN_ROOT, "disabled")

# Where generated .ovpn config files are cached.
CLIENTS_DIR = os.path.join(_OPENVPN_ROOT, "clients")

# Mapping file: uid (numeric id as string) -> display name. Used to key
# usage reports by username the way the panel's traffic collector expects.
UID_MAP_FILE = os.path.join(CLIENTS_DIR, "uid_map.json")

# uid_map.json is read on every usage/session poll but changes only when
# users are created/renamed/deleted — cache it keyed by (mtime, size) so the
# hot path skips JSON parsing entirely.
_uid_map_cache: tuple[tuple[float, int], dict] | None = None


def _load_uid_map() -> dict:
    global _uid_map_cache
    try:
        stat = os.stat(UID_MAP_FILE)
    except OSError:
        _uid_map_cache = None
        return {}
    key = (stat.st_mtime, stat.st_size)
    if _uid_map_cache and _uid_map_cache[0] == key:
        return dict(_uid_map_cache[1])
    try:
        with open(UID_MAP_FILE) as f:
            mapping = json.load(f)
    except Exception:
        return {}
    _uid_map_cache = (key, dict(mapping))
    return mapping


def _save_uid_map(mapping: dict) -> None:
    global _uid_map_cache
    try:
        os.makedirs(CLIENTS_DIR, exist_ok=True)
        with open(UID_MAP_FILE, "w") as f:
            json.dump(mapping, f)
        # Restrict read access: uid_map.json maps numeric IDs to usernames —
        # not world-readable. Only the service process needs it.
        os.chmod(UID_MAP_FILE, 0o600)
        _uid_map_cache = None
    except Exception as e:
        logger.error("Failed to save uid map: %s", e)


def _cn_from_uid(uid: str) -> str:
    """Return the OpenVPN CN for a user id.

    The CN is simply the numeric id as a string (e.g. "42").
    This is unambiguous, short, and avoids dashes/special chars
    that cause parsing issues in traffic tracking and mlogin.
    """
    # Accept only alphanumeric/underscore ids (validation done upstream)
    return str(uid).strip()


# Public alias for callers outside this module (e.g. the router).
cn_from_uid = _cn_from_uid


def _get_name(uid: str) -> str | None:
    mapping = _load_uid_map()
    return mapping.get(str(uid))


def _set_name(uid: str, name: str) -> None:
    mapping = _load_uid_map()
    mapping[str(uid)] = name
    _save_uid_map(mapping)


def _remove_name(uid: str) -> None:
    mapping = _load_uid_map()
    uid_str = str(uid)
    if uid_str in mapping:
        del mapping[uid_str]
        _save_uid_map(mapping)


def _client_paths(uid: str) -> dict:
    # CN = user-provided CN (numeric ID). Validate before touching paths.
    # This function is called ONLY after validate_user_id() succeeded, and
    # CNs are passed through validate_client_name() elsewhere.
    cn = _cn_from_uid(uid)
    return {
        "name": cn,
        "ovpn": os.path.join(CLIENTS_DIR, f"{cn}.ovpn"),
        "crt": f"{PKI_DIR}/issued/{cn}.crt",
        "inline": f"{PKI_DIR}/inline/private/{cn}.inline",
        "template": os.path.join(_OPENVPN_ROOT, "server", "client-common.txt"),
        "ccd": os.path.join(_OPENVPN_ROOT, "ccd", cn),
        "limit": os.path.join(LIMITS_DIR, cn),
    }


def set_user_limit(uid: str, max_logins: int) -> bool:
    paths = _client_paths(uid)
    try:
        if max_logins is None:
            return True
        max_logins = int(max_logins)
        if max_logins < 0:
            max_logins = 0
        os.makedirs(LIMITS_DIR, exist_ok=True)
        with open(paths["limit"], "w") as f:
            f.write(str(max_logins))
        logger.info(
            "Set login limit for uid='%s' (cn='%s') to %s",
            uid,
            paths["name"],
            max_logins,
        )
        return True
    except Exception as e:
        logger.error("Error setting login limit for uid='%s': %s", uid, e)
        return False


def remove_user_limit(uid: str) -> None:
    paths = _client_paths(uid)
    try:
        if os.path.exists(paths["limit"]):
            os.remove(paths["limit"])
    except Exception as e:
        logger.error("Error removing login limit for uid='%s': %s", uid, e)


def _generate_ovpn_from_existing_cert(uid: str) -> bool:
    paths = _client_paths(uid)
    try:
        template = paths["template"]
        cert_src = None
        if os.path.exists(paths["inline"]):
            cert_src = paths["inline"]
        elif os.path.exists(paths["crt"]):
            cert_src = paths["crt"]
        else:
            logger.warning("No inline or cert file for uid='%s', cannot generate OVPN", uid)
            return False
        if not os.path.exists(template):
            logger.warning("client-common.txt template missing for uid='%s'", uid)
            return False
        os.makedirs(CLIENTS_DIR, exist_ok=True)
        with open(paths["ovpn"], "w") as out:
            subprocess.run(
                ["grep", "-vh", "^#", template, cert_src],
                stdout=out,
                check=True,
                timeout=30,
            )
            # server.conf uses tls-crypt; the client .ovpn must embed the same
            # pre-shared key inline or the handshake fails.
            tls_block = tls_crypt_block()
            if tls_block:
                out.write(tls_block)
        os.chmod(paths["ovpn"], 0o600)
        logger.info("Regenerated OVPN file for uid='%s' (cn='%s')", uid, paths["name"])
        return True
    except Exception as e:
        logger.error("Failed to regenerate OVPN for uid='%s': %s", uid, e)
        return False


def create_user_on_server(uid: str, name: str, max_logins: int = 1) -> bool:
    """Create a new OpenVPN client certificate.

    The CN is the numeric user id (e.g. "42"). The display name is stored
    separately in uid_map.json for panel use.
    """
    if name:
        _set_name(uid, name)

    paths = _client_paths(uid)
    cn = paths["name"]

    # Already generated -> refresh template and return
    if os.path.exists(paths["ovpn"]):
        if os.path.exists(paths["inline"]):
            _generate_ovpn_from_existing_cert(uid)
        os.makedirs(os.path.join(_OPENVPN_ROOT, "ccd"), exist_ok=True)
        open(paths["ccd"], "a").close()
        set_user_limit(uid, max_logins if max_logins is not None else 1)
        return True

    # Certificate exists but cached .ovpn missing — regenerate
    if os.path.exists(paths["crt"]) or os.path.exists(paths["inline"]):
        if _generate_ovpn_from_existing_cert(uid):
            os.makedirs(os.path.join(_OPENVPN_ROOT, "ccd"), exist_ok=True)
            open(paths["ccd"], "a").close()
            set_user_limit(uid, max_logins if max_logins is not None else 1)
            return True
        logger.error("Client '%s' (uid=%s) exists but OVPN regeneration failed", cn, uid)
        return False

    # Ensure PKI exists before creating client
    if not os.path.exists(os.path.join(PKI_DIR, "ca.crt")):
        logger.error("PKI not initialized — run init_pki() first (container startup).")
        return False

    # Generate client cert with easyrsa
    if not _easyrsa("build-client-full", cn, "nopass"):
        logger.error("Failed to generate client certificate for '%s' (uid=%s)", cn, uid)
        return False

    logger.info("Client certificate generated for cn='%s' (uid=%s)", cn, uid)

    # Generate OVPN file from template + inline cert
    if os.path.exists(paths["inline"]):
        _generate_ovpn_from_existing_cert(uid)

    os.makedirs(os.path.join(_OPENVPN_ROOT, "ccd"), exist_ok=True)
    open(paths["ccd"], "a").close()
    set_user_limit(uid, max_logins if max_logins is not None else 1)

    return os.path.exists(paths["ovpn"])


def delete_user_on_server(uid: str) -> DeleteResult:
    """Delete/revoke a client certificate. Returns a DeleteResult."""
    cn = _cn_from_uid(uid)
    paths = _client_paths(uid)

    # Check if user actually exists
    if not os.path.exists(paths["crt"]) and not os.path.exists(paths["ovpn"]):
        logger.warning("User '%s' (uid=%s) not found on node", cn, uid)
        return DeleteResult.NOT_FOUND

    # Revoke with easyrsa and require both operations to succeed. Removing
    # local files after a failed revoke would leave an untracked valid cert.
    try:
        if os.path.exists(paths["crt"]):
            if not _easyrsa("revoke", cn):
                logger.error("Failed to revoke user '%s'", cn)
                return DeleteResult.FAILED
            if not _easyrsa("gen-crl"):
                logger.error("Failed to regenerate CRL after revoking '%s'", cn)
                return DeleteResult.FAILED
    except Exception as e:
        logger.error("Failed to revoke user '%s': %s", cn, e)
        return DeleteResult.FAILED

    # Remove local files and any explicit disabled marker.
    try:
        os.remove(os.path.join(DISABLED_DIR, _cn_from_uid(uid)))
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("Could not remove disabled marker for uid='%s': %s", uid, e)

    for key in ["ovpn", "crt", "inline", "ccd", "limit"]:
        fpath = paths.get(key)
        if fpath and os.path.exists(fpath):
            try:
                os.remove(fpath)
            except Exception as e:
                logger.warning("Could not remove %s: %s", fpath, e)

    _remove_name(uid)
    logger.info("Revoked and cleaned up user '%s' (uid=%s)", cn, uid)
    return DeleteResult.OK


def change_user_status(uid: str, status: str) -> bool:
    paths = _client_paths(uid)

    disabled_marker = os.path.join(DISABLED_DIR, paths["name"])

    if status == "deactivate":
        try:
            os.makedirs(DISABLED_DIR, exist_ok=True)
            with open(disabled_marker, "w", encoding="utf-8") as f:
                f.write("disabled\n")
            os.chmod(disabled_marker, 0o644)
            if os.path.exists(paths["ccd"]):
                os.remove(paths["ccd"])
            # Best effort disconnect: the disabled marker prevents reconnects
            # even when the management socket is unavailable.
            try:
                from core.openvpn.sessions import disconnect_user

                disconnect_user(paths["name"])
            except Exception as e:
                logger.warning("Could not disconnect disabled uid='%s': %s", uid, e)
            logger.info("Disabled user uid='%s' cn='%s'", uid, paths["name"])
            return True
        except Exception as e:
            logger.error("Error disabling user uid='%s': %s", uid, e)
            return False

    if status == "activate":
        try:
            os.makedirs(os.path.join(_OPENVPN_ROOT, "ccd"), exist_ok=True)
            os.makedirs(DISABLED_DIR, exist_ok=True)
            try:
                os.remove(disabled_marker)
            except FileNotFoundError:
                pass
            with open(paths["ccd"], "w", encoding="utf-8") as f:
                f.write("")
            logger.info("Enabled user uid='%s' cn='%s'", uid, paths["name"])
            return True
        except Exception as e:
            logger.error("Error enabling user uid='%s': %s", uid, e)
            return False

    return False


async def download_ovpn_file(uid: str) -> str | None:
    paths = _client_paths(uid)
    file_path = paths["ovpn"]

    existing_name = _get_name(uid) or uid

    if os.path.exists(paths["inline"]):
        if _generate_ovpn_from_existing_cert(uid):
            return file_path

    if os.path.exists(file_path):
        return file_path

    if create_user_on_server(uid, existing_name):
        return file_path if os.path.exists(file_path) else None

    return None


def get_users_usage() -> dict:
    """Per-user traffic usage in the exact shape OVManager consumes.

    The panel has two independent consumers of GET /sync/usage:

    1. Traffic collector (backend/operations/daily_checks.py):
       iterates ``users`` and resolves each key to a panel user by USERNAME
       (``all_users = {u.name: u}``), then diffs ``sessions[<same key>]``
       per-session. → ``users`` must be keyed by username where known.

    2. Global mlogin (backend/routers/mlogin.py ``_live_sessions``):
       iterates ``sessions`` and resolves each key via ``{str(u.id): u.name}``
       — i.e. it expects numeric-id CN keys. → ``sessions`` must ALSO carry
       the CN key. Unknown keys are skipped harmlessly on both sides.

    So: ``users`` is keyed by username (fallback CN), ``sessions`` carries
    both the CN key and the username alias.
    """
    from core.openvpn.status import parse_usage

    raw = parse_usage() or {"users": {}, "sessions": {}}
    mapping = _load_uid_map()

    users: dict[str, float] = {}
    for cn, total in raw.get("users", {}).items():
        key = mapping.get(cn) or cn
        users[key] = users.get(key, 0) + total

    sessions: dict[str, dict[str, float]] = {}
    for cn, per_session in raw.get("sessions", {}).items():
        sessions[cn] = per_session
        name = mapping.get(cn)
        if name and name != cn:
            sessions[name] = per_session

    return {"users": users, "sessions": sessions}


def display_name_for_cn(cn: str) -> str:
    """Panel username for a CN, falling back to the CN itself."""
    return _load_uid_map().get(str(cn)) or str(cn)
