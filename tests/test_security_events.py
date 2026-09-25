# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Reject classification for the panel's security view.

A reject is not an authentication failure. The max-login hook logs deliberate
policy refusals (disabled user, max logins) next to real breakage (fail-closed
state, unkillable old session) and next to genuine TLS/auth failures that never
reach the hook at all. These tests pin the split so the panel's "auth errors"
badge can only mean the dangerous bucket.
"""

import json
import time
from datetime import datetime

import pytest

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


def test_strict_max_login_line_is_policy(monkeypatch):
    """The hook's strict-reject line says "limit=2", not "max login reached"."""
    _journal(
        monkeypatch,
        [
            _now_prefix(30)
            + "CN=3 ip=1.2.3.4:5000 pool=10.8.0.3 limit=2 active=2 status=2; REJECT",
        ],
    )
    data = sessions.user_diagnostics(hours=8)
    assert data["auth_errors"] == 0
    assert data["warn_rejects"] == 0
    assert data["policy_rejects"] == 1
    assert data["events"][0]["action"] == "max_logins"


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
    monkeypatch.setattr(sessions, "_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "server").mkdir()
    log = tmp_path / "server" / "openvpn.log"
    stamp = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")
    log.write_text(
        f"{stamp} TLS Error: incoming packet authentication failed from [AF_INET]9.9.9.9:1194\n"
        f"{stamp} SIGTERM[soft,remote-exit] received, client-instance exiting\n"
        "Mon Jan  1 00:00:00 2001 TLS Error: certificate revoked from [AF_INET]1.1.1.1:1194\n"
    )

    events = sessions._openvpn_log_events(8)
    # The SIGTERM line is not a failure; the 2001 line is a stamped old event
    # and must be dropped, the current one kept.
    assert len(events) == 1
    ev = events[0]
    assert ev["severity"] == "failure"
    assert ev["action"] == "tls"
    assert ev["peer"] == "9.9.9.9:1194"
    assert ev["ts"] > time.time() - 600


def test_tls_events_have_observed_times_without_log_stamps(monkeypatch, tmp_path):
    """Our log carries no stamps (log-append + --suppress-timestamps), so the
    agent must still give every event a real, stable time."""
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(sessions, "_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "server").mkdir()
    log = tmp_path / "server" / "openvpn.log"
    log.write_text(
        "TLS Error: tls-crypt unwrapping failed from [AF_INET]185.200.116.40:45929\n"
        "tls-crypt unwrap error: packet too short\n"
    )

    first = sessions._openvpn_log_events(8)
    assert len(first) == 1
    assert first[0]["ts"] > time.time() - 60
    assert first[0]["last_seen"] >= first[0]["ts"]
    assert first[0]["count"] == 1  # one failure, not two log lines
    # First sighting is not yet "ongoing": no previous poll to compare with.
    assert first[0]["ongoing"] is False

    seen = sessions._tls_seen_path()
    assert seen.endswith("tls_seen.json")
    stored = json.loads((tmp_path / "state" / "tls_seen.json").read_text())
    assert "185.200.116.40:45929|tls" in stored

    # A second poll keeps the original first-seen time and marks it ongoing.
    second = sessions._openvpn_log_events(8)
    assert second[0]["ts"] == pytest.approx(first[0]["ts"])
    assert second[0]["ongoing"] is True


def test_tls_seen_state_drops_failures_that_stopped(monkeypatch, tmp_path):
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(sessions, "_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "server").mkdir()
    log = tmp_path / "server" / "openvpn.log"
    log.write_text("TLS Error: tls-crypt unwrapping failed from [AF_INET]10.0.0.1:1194\n")
    sessions._openvpn_log_events(8)

    log.write_text("")
    assert sessions._openvpn_log_events(8) == []
    assert json.loads((tmp_path / "state" / "tls_seen.json").read_text()) == {}


def test_tls_seen_state_survives_a_corrupt_file(monkeypatch, tmp_path):
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(sessions, "_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "server").mkdir()
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "tls_seen.json").write_text("{not json")
    log = tmp_path / "server" / "openvpn.log"
    log.write_text("TLS Error: tls-crypt unwrapping failed from [AF_INET]10.0.0.2:1194\n")
    events = sessions._openvpn_log_events(8)
    assert len(events) == 1 and events[0]["ts"] > 0


def test_missing_openvpn_log_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    assert sessions._openvpn_log_events(8) == []


def test_tls_seen_state_is_private(monkeypatch, tmp_path):
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(sessions, "_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "server").mkdir()
    log = tmp_path / "server" / "openvpn.log"
    log.write_text("TLS Error: tls-crypt unwrapping failed from [AF_INET]10.0.0.3:1194\n")
    sessions._openvpn_log_events(8)
    mode = (tmp_path / "state" / "tls_seen.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_pki_does_not_write_log_timestamp(monkeypatch, tmp_path):
    """Regression: `log-timestamp` is not an OpenVPN directive (2.7) and it
    stopped the node from starting. tests/test_server_conf_options.py holds the
    wider guard; this keeps the intent next to the TLS timing tests."""
    from core.openvpn import pki

    monkeypatch.setattr(pki, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(pki, "SERVER_CONF", str(tmp_path / "server" / "server.conf"))
    monkeypatch.setattr(pki, "SCRIPTS_DIR", str(tmp_path / "scripts"))
    conf = pki._fresh_server_conf()
    assert "log-append" in conf
    assert "log-timestamp" not in conf.splitlines()
