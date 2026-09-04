# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""User lifecycle: certificates, profiles, status, limits, usage.

The panel is the source of truth for user identity; here a user is a
certificate CN (the numeric panel id, or a normalized name) plus one folder
of state in :mod:`core.openvpn.store`. This module owns the *lifecycle* —
issue/revoke certs (easyrsa), build .ovpn profiles, enable/disable, login
limits — and reports usage in the exact shape OVManager consumes.
"""

from __future__ import annotations

import os
import subprocess

from core.logger import logger
from core.openvpn import store
from core.openvpn.pki import PKI_DIR, tls_crypt_block
from core.openvpn.pki import run_easyrsa as _easyrsa
from core.validation import DeleteResult

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
CLIENT_TEMPLATE = os.path.join(_OPENVPN_ROOT, "server", "client-common.txt")


def cn_from_uid(uid: str) -> str:
    """The OpenVPN CN for a user id — simply the id as a string (e.g. "42").

    Unambiguous, short, and free of characters that would complicate
    traffic tracking and the mlogin hooks. Validation happens upstream
    (validate_user_id) and again in store path handling.
    """
    return str(uid).strip()


def _cert_paths(cn: str) -> tuple[str, str]:
    """(issued cert, inline bundle) paths inside the PKI."""
    return (
        os.path.join(PKI_DIR, "issued", f"{cn}.crt"),
        os.path.join(PKI_DIR, "inline", "private", f"{cn}.inline"),
    )


# ── profile generation ───────────────────────────────────────────────


def _build_ovpn(cn: str) -> bool:
    """(Re)build users/<cn>/client.ovpn from the template + cert bundle."""
    crt, inline = _cert_paths(cn)
    cert_src = inline if os.path.exists(inline) else crt if os.path.exists(crt) else None
    if cert_src is None:
        logger.warning("No certificate material for cn='%s'; cannot build .ovpn", cn)
        return False
    if not os.path.exists(CLIENT_TEMPLATE):
        logger.warning("client-common.txt missing; cannot build .ovpn for cn='%s'", cn)
        return False
    # The inline bundle is the cert + CA chain; the private key lives next
    # to it and MUST be embedded in the .ovpn or the handshake fails.
    key_path = os.path.join(PKI_DIR, "private", f"{cn}.key")
    if not os.path.exists(key_path):
        logger.warning("No private key for cn='%s'; cannot build .ovpn", cn)
        return False
    try:
        store.create_user(cn)
        out_path = store.ovpn_path(cn)
        with open(out_path, "w") as out:
            subprocess.run(
                ["grep", "-vh", "^#", CLIENT_TEMPLATE, cert_src],
                stdout=out,
                check=True,
                timeout=30,
            )
            # Embed the private key in the standard <key>…</key> block.
            with open(key_path, encoding="utf-8") as kf:
                out.write("<key>\n")
                out.write(kf.read())
                out.write("</key>\n")
            # server.conf uses tls-crypt; the profile must embed the same
            # pre-shared key inline or the handshake fails.
            tls_block = tls_crypt_block()
            if tls_block:
                out.write(tls_block)
        os.chmod(out_path, 0o600)
        logger.info("Built client profile for cn='%s'", cn)
        return True
    except Exception as e:
        logger.error("Failed to build .ovpn for cn='%s': %s", cn, e)
        return False


# ── lifecycle ────────────────────────────────────────────────────────


def create_user_on_server(uid: str, name: str, max_logins: int = 1) -> bool:
    """Create (or repair) a user: cert, profile, name, limit. Idempotent."""
    cn = cn_from_uid(uid)
    crt, inline = _cert_paths(cn)

    # No certificate yet → issue one (needs an initialized PKI). Store state
    # is written only after this succeeds, so a failed create leaves nothing.
    if not os.path.exists(crt) and not os.path.exists(inline):
        if not os.path.exists(os.path.join(PKI_DIR, "ca.crt")):
            logger.error("PKI not initialized — init_pki() runs at startup.")
            return False
        if not _easyrsa("build-client-full", cn, "nopass"):
            logger.error("Certificate generation failed for cn='%s' (uid=%s)", cn, uid)
            return False
        logger.info("Client certificate generated for cn='%s' (uid=%s)", cn, uid)

    # Profile is cheap to rebuild and must reflect the current template.
    if not _build_ovpn(cn) and not os.path.exists(store.ovpn_path(cn)):
        return False

    if name:
        store.set_name(cn, name)
    store.set_limit(cn, max_logins if max_logins is not None else 1)
    return True


def delete_user_on_server(uid: str) -> DeleteResult:
    """Revoke the certificate and remove the user folder."""
    cn = cn_from_uid(uid)
    crt, inline = _cert_paths(cn)

    # A user exists when there is certificate material or a cached profile.
    # A folder holding only a pre-set limit/name (panel may push those before
    # first download) is residue, not a user — clear it and report NOT_FOUND
    # so the panel proceeds with its own cleanup.
    if not os.path.exists(crt) and not os.path.exists(store.ovpn_path(cn)):
        store.delete_user(cn)
        logger.warning("User '%s' (uid=%s) not found on node", cn, uid)
        return DeleteResult.NOT_FOUND

    # Revoke first and require success — deleting local files after a failed
    # revoke would leave an untracked but still-valid certificate.
    if os.path.exists(crt):
        if not _easyrsa("revoke", cn):
            logger.error("Failed to revoke user '%s'", cn)
            return DeleteResult.FAILED
        if not _easyrsa("gen-crl"):
            logger.error("Failed to regenerate CRL after revoking '%s'", cn)
            return DeleteResult.FAILED

    for path in (crt, inline, os.path.join(_OPENVPN_ROOT, "ccd", cn)):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("Could not remove %s: %s", path, e)

    store.delete_user(cn)
    logger.info("Revoked and removed user '%s' (uid=%s)", cn, uid)
    return DeleteResult.OK


def change_user_status(uid: str, status: str) -> bool:
    """Activate/deactivate a user. Deactivation also disconnects live sessions."""
    cn = cn_from_uid(uid)
    if status == "deactivate":
        try:
            store.set_disabled(cn, True)
            # Best-effort disconnect: the disabled marker blocks reconnects
            # even when the management socket is unavailable.
            try:
                from core.openvpn.sessions import disconnect_user

                disconnect_user(cn)
            except Exception as e:
                logger.warning("Could not disconnect disabled uid='%s': %s", uid, e)
            logger.info("Disabled user uid='%s' cn='%s'", uid, cn)
            return True
        except Exception as e:
            logger.error("Error disabling user uid='%s': %s", uid, e)
            return False
    if status == "activate":
        try:
            store.set_disabled(cn, False)
            logger.info("Enabled user uid='%s' cn='%s'", uid, cn)
            return True
        except Exception as e:
            logger.error("Error enabling user uid='%s': %s", uid, e)
            return False
    return False


def set_user_limit(uid_or_name: str, max_logins: int) -> bool:
    """Set max simultaneous logins. Accepts a user id OR a panel username —
    the panel sends the name when it has no id. Usernames are resolved to
    the CN so the connect hook (which only knows CNs) always finds the limit.
    """
    if max_logins is None:
        return True
    cn = cn_from_uid(uid_or_name)
    if not store.user_exists(cn):
        cn = store.cn_for_name(str(uid_or_name)) or cn
    try:
        store.set_limit(cn, int(max_logins))
        logger.info("Set login limit for cn='%s' to %s", cn, max(0, int(max_logins)))
        return True
    except Exception as e:
        logger.error("Error setting login limit for '%s': %s", uid_or_name, e)
        return False


async def download_ovpn_file(uid: str) -> str | None:
    """Path to the user's .ovpn, creating cert/profile lazily if needed."""
    cn = cn_from_uid(uid)
    _, inline = _cert_paths(cn)

    if os.path.exists(inline) and _build_ovpn(cn):
        return store.ovpn_path(cn)
    if os.path.exists(store.ovpn_path(cn)):
        return store.ovpn_path(cn)
    if create_user_on_server(uid, store.get_name(cn) or ""):
        path = store.ovpn_path(cn)
        return path if os.path.exists(path) else None
    return None


# ── usage reporting ──────────────────────────────────────────────────


def get_users_usage() -> dict:
    """Per-user traffic usage in the exact shape OVManager consumes.

    The panel has two independent consumers of GET /sync/usage:

    1. Traffic collector (backend/operations/daily_checks.py): resolves
       ``users`` keys by USERNAME → keyed by username where known.
    2. Global mlogin (backend/routers/mlogin.py): resolves ``sessions`` keys
       by numeric-id CN → ``sessions`` must ALSO carry the CN key.

    So ``users`` is keyed by username (fallback CN) and ``sessions`` carries
    both the CN key and the username alias.

    ``totals`` is additive (ignored by current panels): lifetime bytes per
    user = completed sessions (accumulated by the disconnect hook) + live
    sessions — the number an operator actually means by "user usage".
    """
    from core.openvpn.status import parse_usage

    raw = parse_usage() or {"users": {}, "sessions": {}}
    names = store.name_map()

    users: dict[str, float] = {}
    for cn, total in raw.get("users", {}).items():
        key = names.get(cn) or cn
        users[key] = users.get(key, 0) + total

    sessions: dict[str, dict[str, float]] = {}
    for cn, per_session in raw.get("sessions", {}).items():
        sessions[cn] = per_session
        name = names.get(cn)
        if name and name != cn:
            sessions[name] = per_session

    totals: dict[str, float] = {}
    for cn, banked in store.all_accumulated_usage().items():
        key = names.get(cn) or cn
        totals[key] = totals.get(key, 0) + banked
    for key, live in users.items():
        totals[key] = totals.get(key, 0) + live

    return {"users": users, "sessions": sessions, "totals": totals}


def display_name_for_cn(cn: str) -> str:
    """Panel username for a CN, falling back to the CN itself."""
    return store.name_map().get(str(cn)) or str(cn)
