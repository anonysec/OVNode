# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""What each reader does with bytes that are not UTF-8, decided per site.

`errors="ignore"` silently drops an undecodable byte and keeps the rest of the
line — and of the file. For a stream whose lines are independent that is the
right call: one bad byte must not cost the panel its whole window of events.
For a small machine-written file whose fields are matched against live
sessions it is not: half a name decoded cleanly is a marker that silently
never matches. Ruled here, with a test each side of the line:

* session markers  — strict. Corrupt file: skipped with a warning, the rest
  of the markers unaffected, and the poll still answers.
* hook event log   — ignore. Lines are independent; a strict read would hand
  the panel an empty event window for as long as the bad byte is in the file.
* openvpn.log tail — ignore. The log carries client-supplied bytes, and the
  TLS failures it reports are the panel's only danger signal: losing the
  whole tail to one bad byte is worse than one garbled reason string.
"""

import time

from backend.openvpn import sessions


def test_a_corrupt_marker_is_skipped_with_a_warning(tmp_path, monkeypatch, caplog):
    """A marker is a key=value file matched against live sessions: a corrupt
    one is garbage, not a session. Skip it, say so, keep the others."""
    monkeypatch.setattr(sessions, "SESSIONS_DIR", str(tmp_path))
    (tmp_path / "alice").write_bytes(
        b"common_name=alice\nifconfig_pool_remote_ip=10.8.0.2\ncreated=1700000000\n"
    )
    (tmp_path / "bob").write_bytes(
        b"common_name=bo\xffb\nifconfig_pool_remote_ip=10.8.0.3\ncreated=1700000001\n"
    )

    with caplog.at_level("WARNING", logger="ovnode"):
        rows = sessions._read_active_files()

    assert {row["common_name"] for row in rows} == {"alice"}
    assert any("Failed to read active marker" in rec.message for rec in caplog.records), [
        rec.message for rec in caplog.records
    ]


def test_a_bad_byte_in_the_hook_log_keeps_every_line(tmp_path, monkeypatch):
    """The hook log is a stream: one undecodable line must not cost the poll
    its events, which is what a strict read of the file would do."""
    now = int(time.time())
    log = tmp_path / "hook-events.log"
    log.write_bytes(
        f"{now} [ovnode-mlogin] CN=u1 limit=1; REJECT\n".encode()
        + f"{now} [ovnode-mlogin] CN=u\xff2 limit=1; REJECT\n".encode("latin-1")
        + f"{now} [ovnode-mlogin] CN=u3 ip=1.2.3.4:5000; ALLOW\n".encode()
    )
    monkeypatch.setenv("OVNODE_LOG_FILE", str(log))
    sessions._journal_cache.clear()

    lines = sessions._journal_lines(8)

    assert len(lines) == 3, lines
    assert any("u1" in line for line in lines) and any("u3" in line for line in lines), lines


def test_invalid_bytes_in_the_openvpn_log_keep_the_tls_failures(tmp_path, monkeypatch):
    """openvpn.log carries client-supplied bytes. The TLS failures in it are
    the panel's only danger badge — the tail must survive a bad byte."""
    server = tmp_path / "server"
    server.mkdir()
    (server / "openvpn.log").write_bytes(
        b"TLS Error: packet authentication failed from [AF_INET]198.51.100.9:41194\n"
        b"peer \xff\xfe CN=weird TLS Error: SSL error [AF_INET]198.51.100.9:41195\n"
    )
    monkeypatch.setattr(sessions, "_OPENVPN_ROOT", str(tmp_path))

    lines = sessions._openvpn_log_lines()

    assert len(lines) == 2, lines
    assert all("TLS Error" in line for line in lines), lines
