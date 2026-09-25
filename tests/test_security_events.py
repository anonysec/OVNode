# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Reject classification for the panel's security view.

A reject is not an authentication failure. The max-login hook logs deliberate
policy refusals (disabled user, max logins) next to real breakage (fail-closed
state, unkillable old session) and next to genuine TLS/auth failures that never
reach the hook at all. These tests pin the split so the panel's "auth errors"
badge can only mean the dangerous bucket.
"""

import time
from datetime import datetime

import core.openvpn.sessions as sessions


def _journal(monkeypatch, lines):
    monkeypatch.setattr(sessions, "_journal_lines", lambda hours: list(lines))
    monkeypatch.setattr(sessions, "_openvpn_log_events", lambda hours: [])


def _now_prefix(offset_s=0.0):
    return f"{time.time() - offset_s:.6f} host ovnode-mlogin: "


def test_disabled_user_reject_is_policy_not_auth_error(monkeypatch):
    _journal(
        monkeypatch,
        [
            _now_prefix(30) + "CN=7 ip=1.2.3.4:5000 is disabled; REJECT",
            _now_prefix(10) + "CN=7 ip=1.2.3.4:5001 is disabled; REJECT",
        ],
    )
    data = sessions.user_diagnostics(hours=8)

    assert data["rejects"] == 2
    assert data["auth_errors"] == 0
    assert data["policy_rejects"] == 2
    assert data["failures"] == 0
    assert data["events"][0]["action"] == "disabled"
    assert data["events"][0]["severity"] == "policy"
    assert data["events"][0]["ts"] > 0
    # Per-user reject counts still exist, just not as auth errors.
    assert data["rejects_by_cn"]
    assert all(v == 0 for v in data["auth_errors_by_cn"].values())


def test_fail_closed_and_takeover_failure_are_danger(monkeypatch):
    _journal(
        monkeypatch,
        [
            _now_prefix(120) + "CN=8 USERS_DIR missing or not a directory — fail-closed; REJECT",
            _now_prefix(60)
            + "CN=8 ip=1.2.3.4:5000 pool=10.8.0.9 takeover could not verify"
            " old session termination; REJECT",
        ],
    )
    data = sessions.user_diagnostics(hours=8)

    assert data["auth_errors"] == 2
    assert data["failures"] == 2
    assert data["policy_rejects"] == 0
    assert {e["action"] for e in data["events"]} == {"fail_closed", "takeover_failed"}


def test_unclassified_reject_is_warn_not_danger(monkeypatch):
    _journal(monkeypatch, [_now_prefix(5) + "CN=9 something unexpected happened; REJECT"])
    data = sessions.user_diagnostics(hours=8)

    assert data["auth_errors"] == 0
    assert data["rejects"] == 1
    assert data["events"][0]["severity"] == "warn"
    assert data["events"][0]["action"] == "other"


def test_events_carry_real_timestamps_and_newest_first(monkeypatch):
    _journal(
        monkeypatch,
        [
            _now_prefix(300) + "CN=1 limit=1 active=2 status=2; REJECT",
            _now_prefix(5) + "CN=2 is disabled; REJECT",
        ],
    )
    data = sessions.user_diagnostics(hours=8)
    stamps = [e["ts"] for e in data["events"]]
    assert stamps == sorted(stamps, reverse=True)
    assert stamps[0] - stamps[1] > 200


def test_journal_line_without_epoch_is_kept_but_undated(monkeypatch):
    _journal(monkeypatch, ["Jul 25 01:02:03 host ovnode-mlogin: CN=3 is disabled; REJECT"])
    data = sessions.user_diagnostics(hours=8)
    assert data["rejects"] == 1
    assert data["events"][0]["ts"] == 0.0


def test_tls_log_scan_reports_real_handshake_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    (tmp_path / "server").mkdir()
    log = tmp_path / "server" / "openvpn.log"
    stamp = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")
    log.write_text(
        f"{stamp} TLS Error: incoming packet authentication failed from [AF_INET]9.9.9.9:1194\n"
        f"{stamp} SIGTERM[soft,remote-exit] received, client-instance exiting\n"
        "Mon Jan  1 00:00:00 2001 TLS Error: certificate revoked\n"
    )

    events = sessions._openvpn_log_events(8)
    # The fresh TLS error is kept; the year-2001 one is outside the window.
    assert len(events) == 1
    ev = events[0]
    assert ev["severity"] == "failure"
    assert ev["action"] == "tls"
    assert ev["peer"] == "9.9.9.9:1194"
    assert ev["ts"] > time.time() - 600


def test_missing_openvpn_log_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    assert sessions._openvpn_log_events(8) == []


def test_pki_writes_log_timestamp(monkeypatch, tmp_path):
    from core.openvpn import pki

    monkeypatch.setattr(pki, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(pki, "SERVER_CONF", str(tmp_path / "server" / "server.conf"))
    monkeypatch.setattr(pki, "SCRIPTS_DIR", str(tmp_path / "scripts"))
    conf = pki._fresh_server_conf()
    assert "log-timestamp" in conf.splitlines()
