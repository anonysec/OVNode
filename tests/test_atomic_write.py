# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""One atomic-write helper, and it is actually atomic.

server.conf is the only copy of the OpenVPN config: a crash or power loss
between truncate and write leaves a file OpenVPN refuses to start on. The
helper was extracted because three modules had drifted into two copies plus a
plain ``open(..., "w")``.
"""

import os
import stat

import pytest


def test_writes_the_content(tmp_path):
    from backend.openvpn.atomic import write_text_atomic

    target = tmp_path / "server.conf"
    write_text_atomic(str(target), "port 1194\n")
    assert target.read_text() == "port 1194\n"


def test_creates_the_parent_directory(tmp_path):
    from backend.openvpn.atomic import write_text_atomic

    target = tmp_path / "server" / "nested" / "server.conf"
    write_text_atomic(str(target), "port 1194\n")
    assert target.read_text() == "port 1194\n"


def test_applies_the_requested_mode(tmp_path):
    """mkstemp makes 0600; a dropped-privilege OpenVPN user must still read it."""
    from backend.openvpn.atomic import write_text_atomic

    target = tmp_path / "server.conf"
    write_text_atomic(str(target), "x")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_keeps_a_backup_when_asked(tmp_path):
    from backend.openvpn.atomic import write_text_atomic

    target = tmp_path / "server.conf"
    write_text_atomic(str(target), "old\n", keep_backup=True)
    write_text_atomic(str(target), "new\n", keep_backup=True)
    assert target.read_text() == "new\n"
    assert (tmp_path / "server.conf.bak").read_text() == "old\n"


def test_no_backup_when_not_asked(tmp_path):
    from backend.openvpn.atomic import write_text_atomic

    target = tmp_path / "state"
    write_text_atomic(str(target), "old\n")
    write_text_atomic(str(target), "new\n")
    assert not (tmp_path / "state.bak").exists()


def test_a_failed_write_leaves_the_old_content_intact(tmp_path, monkeypatch):
    """The whole point: a reader never sees a half-written file."""
    from backend.openvpn import atomic

    target = tmp_path / "server.conf"
    target.write_text("original\n")

    def exploding_replace(src, dst):
        raise OSError("simulated crash before rename")

    monkeypatch.setattr(atomic.os, "replace", exploding_replace)
    with pytest.raises(OSError):
        atomic.write_text_atomic(str(target), "replacement\n")

    assert target.read_text() == "original\n"


def test_no_temp_files_are_left_behind(tmp_path, monkeypatch):
    from backend.openvpn import atomic

    target = tmp_path / "server.conf"

    def exploding_replace(src, dst):
        raise OSError("boom")

    monkeypatch.setattr(atomic.os, "replace", exploding_replace)
    with pytest.raises(OSError):
        atomic.write_text_atomic(str(target), "x")

    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp-")]
    assert leftovers == [], f"temp files leaked: {leftovers}"


def test_pki_creates_server_conf_atomically(monkeypatch, tmp_path):
    """The PKI hardening path must not use a plain open(..., "w")."""
    from backend.openvpn import pki

    target = tmp_path / "server.conf"
    monkeypatch.setattr(pki, "SERVER_CONF", str(target))
    monkeypatch.setattr(pki, "_fresh_server_conf", lambda: "port 1194\nproto udp\n")

    assert pki._ensure_server_conf() is True
    assert target.read_text() == "port 1194\nproto udp\n"
