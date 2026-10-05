# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Dynamic-IP reconnect races in the client-connect hook.

Executes the REAL ovnode-client-connect.sh against a tmp user/marker tree
and a fake OpenVPN management server. Covers the exact failure users saw:
a legitimate max_logins=1 reconnect rejected because takeover verification
read the 5s-cadence status file 0.3s after the kill.

Status file layout is status-version 3 (tab-separated); the hook reads
$2=CN, $4=pool IP, $11=CID.
"""

import os
import socket
import subprocess
import tempfile
import threading
import time

from core.openvpn import sessions as sess_mod

HOOK = os.path.join(os.path.dirname(__file__), "..", "core", "scripts", "ovnode-client-connect.sh")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeMgmt:
    """Minimal management interface: banner, optional password, then one
    command per connection. `status 2` replays a scripted sequence of row
    sets (one per call); client-kill always SUCCESS (and records CIDs)."""

    def __init__(self, status_script=(), password="testpw"):
        self._status_script = list(status_script)
        self._password = password
        self.killed = []
        self.conns = 0
        self.port = _free_port()
        self._stop = threading.Event()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(50)
        self._srv.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        self.conns += 1
        try:
            conn.settimeout(5)
            conn.sendall(b">INFO:OpenVPN Management Interface\r\nENTER PASSWORD:\r\n")
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                data += chunk
            # Real management is a session: loop commands until quit/close.
            while True:
                cmd = b""
                while b"\n" not in cmd:
                    try:
                        chunk = conn.recv(4096)
                    except TimeoutError:
                        return
                    if not chunk:
                        return
                    cmd += chunk
                text = cmd.decode(errors="ignore").strip()
                if text == "quit":
                    return
                if text.startswith("client-kill"):
                    parts = text.split()
                    if len(parts) >= 2:
                        self.killed.append(parts[1])
                    conn.sendall(b"SUCCESS: client-kill command succeeded\r\n")
                elif text.startswith("status"):
                    if self._status_script:
                        rows = self._status_script.pop(0)
                    else:
                        rows = []
                    body = "".join(
                        f"CLIENT_LIST,{r[0]},{r[1]},{r[2]},0,0,now,0,{r[3]}\r\n" for r in rows
                    )
                    conn.sendall(("HEADER,CLIENT_LIST,Common Name\r\n" + body + "END\r\n").encode())
                else:
                    conn.sendall(b"SUCCESS: ok\r\nEND\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass


def _status_row(cn, real, pool, cid, time_t="1700000000"):
    fields = ["CLIENT_LIST", cn, real, pool, "10", "20", "now", time_t, cn, "", str(cid)]
    while len(fields) < 11:
        fields.append("")
    return "\t".join(fields[:11])


def test_corpse_reconnect_allowed_after_kill():
    """The reported bug: old (CN, old-pool) corpse still in the status file,
    new IP/pool arrives. Kill succeeds; mgmt status drops the row; ALLOW."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = tmp
        users = os.path.join(root, "users")
        sessions = os.path.join(root, "sessions")
        server = os.path.join(root, "server")
        os.makedirs(users)
        os.makedirs(sessions)
        os.makedirs(server)
        open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
        status = os.path.join(server, "status.log")
        # Corpse row: file is NOT rewritten by the kill (5s cadence).
        corpse = _status_row("u1", "5.5.5.5:4000", "10.8.0.1", 7)
        open(status, "w").write("HEADER\tX\n" + corpse + "\n")
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("1")
        now = int(time.time())
        open(os.path.join(sessions, "u1.10.8.0.1"), "w").write(
            "common_name=u1\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
            f"ifconfig_pool_remote_ip=10.8.0.1\ncreated={now - 60}\n"
        )
        # mgmt: kill OK; first status shows corpse, then clean.
        mgmt = FakeMgmt(
            status_script=[
                [("u1", "5.5.5.5:4000", "10.8.0.1", "u1")],
                [],
            ]
        )
        try:
            env = {
                **os.environ,
                "OVNODE_USERS_DIR": users,
                "OVNODE_SESSIONS_DIR": sessions,
                "OVNODE_STATUS_FILE": status,
                "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
                "OVNODE_MANAGEMENT_PORT": str(mgmt.port),
                "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
                "common_name": "u1",
                "trusted_ip": "9.9.9.9",
                "trusted_port": "5001",
                "ifconfig_pool_remote_ip": "10.8.0.2",
            }
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 0, f"hook rejected legit reconnect: {r.stderr}"
            assert mgmt.killed == ["7"], f"expected CID kill, got {mgmt.killed}"
            assert os.path.exists(os.path.join(sessions, "u1.10.8.0.2")), "fresh marker missing"
            assert not os.path.exists(os.path.join(sessions, "u1.10.8.0.1")), "corpse marker kept"
        finally:
            mgmt.close()


def test_live_second_device_rejected():
    """A genuinely live session must still block a second device (limit=1)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
        status = os.path.join(server, "status.log")
        # mgmt status NEVER drops the row (kill ignored / session really live
        # and re-pushed): 14+ identical replies exhaust the 7s verify budget.
        live = [("u1", "5.5.5.5:4000", "10.8.0.1", "u1")]
        mgmt = FakeMgmt(status_script=[list(live)] * 30)
        try:
            open(status, "w").write(
                "HEADER\tX\n" + _status_row("u1", "5.5.5.5:4000", "10.8.0.1", 7) + "\n"
            )
            os.makedirs(os.path.join(users, "u1"))
            open(os.path.join(users, "u1", "limit"), "w").write("1")
            now = int(time.time())
            open(os.path.join(sessions, "u1.10.8.0.1"), "w").write(
                "common_name=u1\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
                f"ifconfig_pool_remote_ip=10.8.0.1\ncreated={now - 60}\n"
            )
            env = {
                **os.environ,
                "OVNODE_USERS_DIR": users,
                "OVNODE_SESSIONS_DIR": sessions,
                "OVNODE_STATUS_FILE": status,
                "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
                "OVNODE_MANAGEMENT_PORT": str(mgmt.port),
                "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
                "common_name": "u1",
                "trusted_ip": "9.9.9.9",
                "trusted_port": "5001",
                "ifconfig_pool_remote_ip": "10.8.0.2",
            }
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 1, "live second device must be rejected"
            assert not os.path.exists(os.path.join(sessions, "u1.10.8.0.2"))
        finally:
            mgmt.close()


def test_grace_absorbs_reaped_session():
    """Fresh marker (<15s) whose pool is already gone from status: the old
    daemon row was reaped — absorb, don't force a takeover cycle."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
        status = os.path.join(server, "status.log")
        open(status, "w").write("HEADER\tX\n")  # empty: corpse reaped
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("1")
        now = int(time.time())
        open(os.path.join(sessions, "u1.10.8.0.1"), "w").write(
            "common_name=u1\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
            f"ifconfig_pool_remote_ip=10.8.0.1\ncreated={now - 5}\n"
        )
        mgmt = FakeMgmt(status_script=[[]] * 5)
        try:
            env = {
                **os.environ,
                "OVNODE_USERS_DIR": users,
                "OVNODE_SESSIONS_DIR": sessions,
                "OVNODE_STATUS_FILE": status,
                "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
                "OVNODE_MANAGEMENT_PORT": str(mgmt.port),
                "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
                "common_name": "u1",
                "trusted_ip": "9.9.9.9",
                "trusted_port": "5001",
                "ifconfig_pool_remote_ip": "10.8.0.2",
            }
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 0, r.stderr
            assert mgmt.killed == [], f"no kill needed, got {mgmt.killed}"
            assert os.path.exists(os.path.join(sessions, "u1.10.8.0.2"))
        finally:
            mgmt.close()


def test_mgmt_down_degrades_for_limit1():
    """Management socket down + limit=1: allow with replaced markers
    (corpse reaped by ping-restart) instead of rejecting."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        status = os.path.join(server, "status.log")
        open(status, "w").write(
            "HEADER\tX\n" + _status_row("u1", "5.5.5.5:4000", "10.8.0.1", 7) + "\n"
        )
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("1")
        now = int(time.time())
        open(os.path.join(sessions, "u1.10.8.0.1"), "w").write(
            "common_name=u1\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
            f"ifconfig_pool_remote_ip=10.8.0.1\ncreated={now - 60}\n"
        )
        closed = _free_port()  # nothing listening: mgmt down
        env = {
            **os.environ,
            "OVNODE_USERS_DIR": users,
            "OVNODE_SESSIONS_DIR": sessions,
            "OVNODE_STATUS_FILE": status,
            "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
            "OVNODE_MANAGEMENT_PORT": str(closed),
            "common_name": "u1",
            "trusted_ip": "9.9.9.9",
            "trusted_port": "5001",
            "ifconfig_pool_remote_ip": "10.8.0.2",
        }
        r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
        assert r.returncode == 0, f"degrade expected, got reject: {r.stderr}"
        assert os.path.exists(os.path.join(sessions, "u1.10.8.0.2"))
        assert not os.path.exists(os.path.join(sessions, "u1.10.8.0.1"))


def test_mgmt_down_still_rejects_limit2():
    """Strict case stays fail-closed when mgmt is down."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        status = os.path.join(server, "status.log")
        open(status, "w").write(
            "HEADER\tX\n"
            + _status_row("u1", "5.5.5.5:4000", "10.8.0.1", 7)
            + "\n"
            + _status_row("u1", "6.6.6.6:4001", "10.8.0.3", 9)
            + "\n"
        )
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("2")
        closed = _free_port()
        env = {
            **os.environ,
            "OVNODE_USERS_DIR": users,
            "OVNODE_SESSIONS_DIR": sessions,
            "OVNODE_STATUS_FILE": status,
            "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
            "OVNODE_MANAGEMENT_PORT": str(closed),
            "common_name": "u1",
            "trusted_ip": "9.9.9.9",
            "trusted_port": "5001",
            "ifconfig_pool_remote_ip": "10.8.0.2",
        }
        r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
        assert r.returncode == 1, "over-limit with mgmt down must reject"


def test_pool_reuse_takeover_kills_same_pool_corpse():
    """ipp.txt recycled the dead session's pool IP: the corpse row carries
    the NEW pool. Takeover must still kill it (by CID) and allow."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
        status = os.path.join(server, "status.log")
        open(status, "w").write(
            "HEADER\tX\n" + _status_row("u1", "5.5.5.5:4000", "10.8.0.2", 7) + "\n"
        )
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("1")
        now = int(time.time())
        open(os.path.join(sessions, "u1.10.8.0.2"), "w").write(
            "common_name=u1\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
            f"ifconfig_pool_remote_ip=10.8.0.2\ncreated={now - 60}\n"
        )
        mgmt = FakeMgmt(
            status_script=[
                [("u1", "5.5.5.5:4000", "10.8.0.2", "u1")],
                [],
            ]
        )
        try:
            env = {
                **os.environ,
                "OVNODE_USERS_DIR": users,
                "OVNODE_SESSIONS_DIR": sessions,
                "OVNODE_STATUS_FILE": status,
                "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
                "OVNODE_MANAGEMENT_PORT": str(mgmt.port),
                "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
                "common_name": "u1",
                "trusted_ip": "9.9.9.9",
                "trusted_port": "5001",
                "ifconfig_pool_remote_ip": "10.8.0.2",
            }
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 0, f"pool-reuse corpse must be taken over: {r.stderr}"
            assert mgmt.killed == ["7"]
        finally:
            mgmt.close()


def test_rapid_flap_all_reconnects_allowed():
    """Dynamic-IP flap: three rapid reconnects, each arriving while the
    previous corpse is still listed. Every reconnect must be allowed and
    exactly one marker must remain at the end."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
        status = os.path.join(server, "status.log")
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("1")
        # Each round: mgmt sees the previous corpse once, then clean.
        script = []
        for i in range(3):
            script.append([("u1", f"5.5.5.{i}:4000", f"10.8.0.{i + 1}", "u1")])
            script.append([])
        mgmt = FakeMgmt(status_script=script)
        try:
            base_env = {
                **os.environ,
                "OVNODE_USERS_DIR": users,
                "OVNODE_SESSIONS_DIR": sessions,
                "OVNODE_STATUS_FILE": status,
                "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
                "OVNODE_MANAGEMENT_PORT": str(mgmt.port),
                "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
                "common_name": "u1",
            }
            for i in range(3):
                pool = f"10.8.0.{i + 1}"
                # Status file still lists the previous corpse (5s lag).
                prev = f"10.8.0.{i}" if i else "10.8.0.9"
                row = _status_row("u1", f"5.5.5.{i}:4000", prev, 7 + i)
                with open(status, "w") as f:
                    f.write("HEADER\tX\n" + row + "\n")
                env = {
                    **base_env,
                    "trusted_ip": f"9.9.9.{i}",
                    "trusted_port": str(5001 + i),
                    "ifconfig_pool_remote_ip": pool,
                }
                r = subprocess.run(
                    ["bash", HOOK], capture_output=True, text=True, timeout=60, env=env
                )
                assert r.returncode == 0, f"flap round {i} rejected: {r.stderr}"
            leftovers = sorted(n for n in os.listdir(sessions) if not n.startswith(".lock"))
            assert leftovers == ["u1.10.8.0.3"], f"marker churn: {leftovers}"
            assert sorted(mgmt.killed) == ["7", "8", "9"], mgmt.killed
        finally:
            mgmt.close()


def test_parallel_full_reject_all_and_touch_nothing():
    """Chaos 1: 8 parallel connects against 3 live rows (limit=3).
    Nothing mutates mid-run, so every hook must deterministically REJECT
    without touching mgmt or markers — per-CN locking must not deadlock."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
        status = os.path.join(server, "status.log")
        with open(status, "w") as f:
            f.write("HEADER\tX\n")
            for i, pool in enumerate(("10.8.0.1", "10.8.0.2", "10.8.0.3")):
                f.write(_status_row("u1", f"5.5.5.{i}:4000", pool, 7 + i) + "\n")
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("3")
        mgmt = FakeMgmt(status_script=[])
        try:
            base_env = {
                **os.environ,
                "OVNODE_USERS_DIR": users,
                "OVNODE_SESSIONS_DIR": sessions,
                "OVNODE_STATUS_FILE": status,
                "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
                "OVNODE_MANAGEMENT_PORT": str(mgmt.port),
                "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
                "common_name": "u1",
            }
            procs = []
            for i in range(8):
                env = {
                    **base_env,
                    "trusted_ip": f"9.9.9.{i}",
                    "trusted_port": str(5001 + i),
                    "ifconfig_pool_remote_ip": f"10.8.1.{i}",
                }
                procs.append(
                    subprocess.Popen(
                        ["bash", HOOK],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=env,
                    )
                )
            rcs = [p.wait(timeout=60) for p in procs]
            assert rcs == [1] * 8, f"all must reject: {rcs}"
            leftovers = [n for n in os.listdir(sessions) if not n.startswith(".lock")]
            assert leftovers == [], f"markers written on reject: {leftovers}"
            assert mgmt.conns == 0, "limit>1 reject must not touch mgmt"
        finally:
            mgmt.close()


def test_parallel_degrade_converges_to_one_marker():
    """Chaos 2: 8 parallel limit=1 connects, empty status, mgmt down.
    Every hook degrades (ALLOW + replace markers) — final state must be
    exactly one marker regardless of interleaving."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users = os.path.join(tmp, "users")
        sessions = os.path.join(tmp, "sessions")
        server = os.path.join(tmp, "server")
        for d in (users, sessions, server):
            os.makedirs(d)
        status = os.path.join(server, "status.log")
        open(status, "w").write("HEADER\tX\n")
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "limit"), "w").write("1")
        closed = _free_port()
        base_env = {
            **os.environ,
            "OVNODE_USERS_DIR": users,
            "OVNODE_SESSIONS_DIR": sessions,
            "OVNODE_STATUS_FILE": status,
            "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
            "OVNODE_MANAGEMENT_PORT": str(closed),
            "common_name": "u1",
        }
        procs = []
        for i in range(8):
            env = {
                **base_env,
                "trusted_ip": f"9.9.9.{i}",
                "trusted_port": str(5001 + i),
                "ifconfig_pool_remote_ip": f"10.8.1.{i}",
            }
            procs.append(
                subprocess.Popen(
                    ["bash", HOOK],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
            )
        rcs = [p.wait(timeout=60) for p in procs]
        assert rcs == [0] * 8, f"all must degrade-allow: {rcs}"
        leftovers = sorted(n for n in os.listdir(sessions) if not n.startswith(".lock"))
        assert len(leftovers) == 1, f"must converge to one marker: {leftovers}"


def test_disconnect_only_stale_keeps_live():
    """disconnect_user(only_stale=True) removes the dead marker and keeps
    the live session untouched (no mgmt kill attempted)."""
    with tempfile.TemporaryDirectory() as tmp:
        # Point the sessions dir at tmp (restored after the test).
        old_sessions = sess_mod.SESSIONS_DIR
        sess_mod.SESSIONS_DIR = tmp
        now = int(time.time())
        with open(os.path.join(tmp, "u1.10.8.0.1"), "w") as f:
            f.write(
                "common_name=u1\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n"
                f"ifconfig_pool_remote_ip=10.8.0.1\ncreated={now - 600}\n"
            )
        with open(os.path.join(tmp, "u1.10.8.0.2"), "w") as f:
            f.write(
                "common_name=u1\ntrusted_ip=9.9.9.9\ntrusted_port=5001\n"
                f"ifconfig_pool_remote_ip=10.8.0.2\ncreated={now - 5}\n"
            )
        status_path = os.path.join(tmp, "status.log")
        with open(status_path, "w") as f:
            f.write("HEADER\tX\n" + _status_row("u1", "9.9.9.9:5001", "10.8.0.2", 9) + "\n")
        # parse_sessions reads the canonical path; monkeypatch it.
        orig_parse = sess_mod._read_status_sessions
        sess_mod._read_status_sessions = lambda: [
            {
                "common_name": "u1",
                "virtual_address": "10.8.0.2",
                "trusted_ip": "9.9.9.9",
                "trusted_port": "5001",
                "client_id": "9",
            }
        ]
        orig_diag = sess_mod.user_diagnostics
        sess_mod.user_diagnostics = lambda **kw: {}
        try:
            out = sess_mod.disconnect_user("u1", only_stale=True)
            assert out["removed_markers"] == ["u1.10.8.0.1"], out
            assert os.path.exists(os.path.join(tmp, "u1.10.8.0.2")), "live marker removed!"
        finally:
            sess_mod._read_status_sessions = orig_parse
            sess_mod.user_diagnostics = orig_diag
            sess_mod.SESSIONS_DIR = old_sessions


def _hook_env(users, sessions, server, status, mgmt_port, cn="u1", pool="10.8.0.2"):
    return {
        **os.environ,
        "OVNODE_USERS_DIR": users,
        "OVNODE_SESSIONS_DIR": sessions,
        "OVNODE_STATUS_FILE": status,
        "OVNODE_MANAGEMENT_HOST": "127.0.0.1",
        "OVNODE_MANAGEMENT_PORT": str(mgmt_port),
        "OVNODE_MGMT_PASS_FILE": os.path.join(server, "mgmt-pass"),
        "common_name": cn,
        "trusted_ip": "9.9.9.9",
        "trusted_port": "5001",
        "ifconfig_pool_remote_ip": pool,
    }


def _mktree(tmp):
    users = os.path.join(tmp, "users")
    sessions = os.path.join(tmp, "sessions")
    server = os.path.join(tmp, "server")
    for d in (users, sessions, server):
        os.makedirs(d)
    open(os.path.join(server, "mgmt-pass"), "w").write("testpw\n")
    status = os.path.join(server, "status.log")
    open(status, "w").write("HEADER\tX\n")
    return users, sessions, server, status


def test_state_file_limit_enforced():
    """Merged `state` file drives the limit exactly like the legacy file."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users, sessions, server, status = _mktree(tmp)
        os.makedirs(os.path.join(users, "u1"))
        with open(os.path.join(users, "u1", "state"), "w") as f:
            f.write("limit=2\ndisabled=0\n")
        with open(status, "w") as f:
            f.write(
                "HEADER\tX\n"
                + _status_row("u1", "5.5.5.5:4000", "10.8.0.1", 7)
                + "\n"
                + _status_row("u1", "6.6.6.6:4001", "10.8.0.3", 9)
                + "\n"
            )
        mgmt = FakeMgmt(status_script=[])
        try:
            env = _hook_env(users, sessions, server, status, mgmt.port)
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 1, "2 live sessions at limit=2 (state) must reject"
            assert mgmt.conns == 0, "limit>1 reject must not touch mgmt"
        finally:
            mgmt.close()


def test_state_file_disabled_rejects():
    """`disabled=1` in the merged file rejects without mgmt traffic."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users, sessions, server, status = _mktree(tmp)
        os.makedirs(os.path.join(users, "u1"))
        with open(os.path.join(users, "u1", "state"), "w") as f:
            f.write("limit=1\ndisabled=1\n")
        mgmt = FakeMgmt(status_script=[])
        try:
            env = _hook_env(users, sessions, server, status, mgmt.port)
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 1, "disabled=1 (state) must reject"
            assert mgmt.conns == 0, "disabled reject must not touch mgmt"
        finally:
            mgmt.close()


def test_legacy_disabled_marker_still_rejects():
    """Pre-merge `disabled` existence marker keeps working (dual-read)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        users, sessions, server, status = _mktree(tmp)
        os.makedirs(os.path.join(users, "u1"))
        open(os.path.join(users, "u1", "disabled"), "w").close()
        mgmt = FakeMgmt(status_script=[])
        try:
            env = _hook_env(users, sessions, server, status, mgmt.port)
            r = subprocess.run(["bash", HOOK], capture_output=True, text=True, timeout=60, env=env)
            assert r.returncode == 1, "legacy disabled marker must reject"
            assert mgmt.conns == 0
        finally:
            mgmt.close()
