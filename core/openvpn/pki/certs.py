# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Certificate lifecycle: CRL freshness, server-cert renewal, tls-crypt key."""

import os
import subprocess
from datetime import UTC

from core.logger import logger
from core.openvpn import pki as _pki

# ── CRL ──────────────────────────────────────────────────────────────

# Regenerate the CRL when it is within this many days of its nextUpdate.
# EasyRSA CRLs are valid for EASYRSA_CRL_DAYS (365); with `crl-verify`,
# OpenVPN rejects ALL clients once the CRL expires — so a node that never
# revokes anyone would lock every user out after a year without this.
_CRL_RENEW_THRESHOLD_DAYS = 30


def _crl_days_remaining() -> int | None:
    """Days until the CRL's nextUpdate, or None when it cannot be read."""
    try:
        out = subprocess.check_output(
            ["openssl", "crl", "-nextupdate", "-noout", "-in", _pki.CRL_FILE],
            text=True,
            timeout=10,
        )
    except Exception as e:
        logger.warning("Could not read CRL nextUpdate: %s", e)
        return None
    return _pki._days_until_openssl_date(out)


_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip


def _days_until_openssl_date(raw: str) -> int | None:
    """Parse 'nextUpdate=Aug 28 12:00:00 2027 GMT' → whole days from now.

    Parsed by hand because openssl always prints English month names while
    strptime('%b') is locale-dependent.
    """
    from datetime import datetime

    try:
        value = raw.split("=", 1)[1].strip()
        month_s, day_s, time_s, year_s, _tz = value.split()
        hour_s, minute_s, second_s = time_s.split(":")
        expiry = datetime(
            int(year_s),
            _pki._MONTHS[month_s],
            int(day_s),
            int(hour_s),
            int(minute_s),
            int(second_s),
            tzinfo=UTC,
        )
        return int((expiry - datetime.now(UTC)).total_seconds() // 86400)
    except (IndexError, KeyError, ValueError) as e:
        logger.warning("Unparseable CRL date %r: %s", raw.strip(), e)
        return None


def renew_server_certificate() -> bool:
    """Renew the OpenVPN server certificate (panel action).

    easyrsa archives the old certificate under ``pki/renewed/`` and issues a
    fresh one; callers restart OpenVPN afterwards so clients pick it up.
    """
    if not os.path.exists(_pki.SERVER_CERT):
        logger.error("Cannot renew server certificate: %s is missing", _pki.SERVER_CERT)
        return False
    if not _pki._easyrsa("renew", "server", "nopass"):
        logger.error("Server certificate renewal failed")
        return False
    logger.info("Server certificate renewed (previous cert archived under renewed/)")
    return True


def crl_is_current() -> bool:
    """True when the CRL was generated after the last PKI change.

    easyrsa's index.txt is updated by revoke/issue; a CRL older than the index
    may not list a just-revoked certificate. Callers use this to decide whether
    a ``gen-crl`` run is still owed before reporting a delete as complete.
    """
    index = os.path.join(_pki.PKI_DIR, "index.txt")
    try:
        return os.path.getmtime(_pki.CRL_FILE) >= os.path.getmtime(index)
    except OSError:
        return False


def _ensure_crl() -> bool:
    """Generate the CRL when missing or near expiry; keep it OpenVPN-readable."""
    if os.path.exists(_pki.CRL_FILE):
        days = _pki._crl_days_remaining()
        if days is not None and days > _pki._CRL_RENEW_THRESHOLD_DAYS:
            try:
                os.chmod(_pki.CRL_FILE, 0o644)
            except OSError:
                pass
            return True
        # Unreadable or expiring: fall through and regenerate. If that fails
        # but the current CRL is still valid, keep serving it.
        logger.warning(
            "CRL expires in %s days (threshold %d) — regenerating",
            days,
            _pki._CRL_RENEW_THRESHOLD_DAYS,
        )
        if not _pki._easyrsa("gen-crl"):
            logger.error("CRL renewal failed — clients will be rejected once it expires!")
            return days is not None and days > 0
        try:
            os.chmod(_pki.CRL_FILE, 0o644)
        except OSError:
            pass
        logger.info("CRL renewed at %s", _pki.CRL_FILE)
        return True
    if not _pki._easyrsa("gen-crl"):
        logger.error("CRL generation failed — revoked certs may remain usable.")
        return False
    if not os.path.exists(_pki.CRL_FILE):
        logger.error("EasyRSA reported CRL success but %s was not created.", _pki.CRL_FILE)
        return False
    try:
        os.chmod(_pki.CRL_FILE, 0o644)
    except OSError:
        pass
    logger.info("Certificate revocation list ready at %s", _pki.CRL_FILE)
    return True


# ── tls-crypt key embedding for .ovpn files ─────────────────────────


def read_tls_crypt_key() -> str | None:
    """Return the tls-crypt pre-shared key, or None if unavailable."""
    try:
        with open(_pki.TLS_KEY, encoding="utf-8") as f:
            key = f.read().strip()
        return key or None
    except OSError as e:
        logger.error("Could not read tls-crypt key %s: %s", _pki.TLS_KEY, e)
        return None


def tls_crypt_block() -> str:
    """The <tls-crypt>…</tls-crypt> block clients need in their .ovpn.

    Generated .ovpn files MUST contain this — server.conf requires tls-crypt,
    so without it the client handshake fails at "TLS key negotiation failed".
    """
    key = _pki.read_tls_crypt_key()
    if not key:
        return ""
    return f"\n<tls-crypt>\n{key}\n</tls-crypt>\n"
