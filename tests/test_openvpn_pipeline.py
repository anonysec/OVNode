# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Functional test of the overhauled OpenVPN PKI/config pipeline.

Runs the whole pipeline in an isolated subprocess with a dedicated
OVNODE_OPENVPN_ROOT, so module-level path constants in core.pki_setup freeze
with the correct env and no state leaks into (or from) other test modules
which share this pytest process.
"""
import os
import subprocess
import sys
import tempfile

CHECK_SCRIPT = r'''
import os, sys

os.environ["OPENVPN_PORT"] = "1194"
os.environ["API_KEY"] = "test-api-key-1234567890"

from core.pki_setup import init_pki, SERVER_CONF, CLIENT_TEMPLATE, TLS_KEY, PKI_DIR

PASS = FAIL = 0
def ok(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {name}")
def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

init_pki()

# fresh PKI
ok(os.path.exists(os.path.join(PKI_DIR, "ca.crt")), "ca cert")
ok(os.path.exists(os.path.join(PKI_DIR, "issued", "server.crt")), "server cert")
ok(os.path.exists(TLS_KEY), "tls key")

conf = read(SERVER_CONF)
ok("management 127.0.0.1 7505" in conf, "management")
ok("management-client-user nobody" in conf, "mgmt user")
ok("tls-crypt" in conf, "tls-crypt")
ok("dh none" in conf, "dh none")
ok("tls-version-min 1.2" in conf, "tls min")
ok("remote-cert-tls client" in conf, "remote-cert-tls")
ok("status-version 2" in conf, "status-version")
ok("writepid" in conf, "writepid")
ok("client-connect" in conf and "client-disconnect" in conf, "hooks")
ok("crl-verify" in conf, "crl")
ok("duplicate-cn" in conf and "max-clients 100" in conf, "mlogin+cap")
ok("explicit-exit-notify 0" in conf, "exit notify")

tpl = read(CLIENT_TEMPLATE)
ok("tls-version-min 1.2" in tpl, "tpl tls min")
ok("remote-cert-tls server" in tpl, "tpl remote-cert-tls")
ok("remote UPDATE_VIA_PANEL 1194" in tpl, "tpl remote")

# client .ovpn embeds tls-crypt
from core.service.user_management import create_user_on_server, _client_paths
uid = "testuser42"
ok(create_user_on_server(uid, "Test User", max_logins=2), "create user")
ovpn = read(_client_paths(uid)["ovpn"])
ok("<tls-crypt>" in ovpn and "</tls-crypt>" in ovpn, "ovpn tls-crypt")
ok("BEGIN OpenVPN Static key" in ovpn, "ovpn key content")
ok("BEGIN CERTIFICATE" in ovpn and "BEGIN PRIVATE KEY" in ovpn, "ovpn cert+key")
ok(read(_client_paths(uid)["limit"]) == "2", "limit file")

# existing conf hardening preserves admin edits
with open(SERVER_CONF, "w") as f:
    f.write(conf + "\n# admin custom line\n")
init_pki()
tuned = read(SERVER_CONF)
ok("# admin custom line" in tuned, "admin line kept")
ok(tuned.count("management 127.0.0.1 7505") == 1, "no dup hardening")

# missing dh file → replaced with dh none
with open(SERVER_CONF, "w") as f:
    f.write(conf.replace("dh none", "dh /etc/openvpn/server/pki/dh.pem") + "\n")
import os as _os
if _os.path.exists("/etc/openvpn/server/pki/dh.pem"):
    _os.remove("/etc/openvpn/server/pki/dh.pem")
init_pki()
dh_fixed = read(SERVER_CONF)
ok("dh none" in dh_fixed, "missing dh replaced with dh none")
ok("dh /etc/openvpn/server/pki/dh.pem" not in dh_fixed, "broken dh reference removed")

# /sync/config
from core.schema.all_schemas import SetSettingsModel
from core.setting.core import change_config
req = SetSettingsModel(
    tunnel_address="vpn.example.com", protocol="udp", ovpn_port=1195, set_new_setting=True
)
ok(change_config(req), "change_config ok")
after = read(SERVER_CONF)
ok("proto udp" in after, "proto udp")
ok("port 1195" in after, "port 1195")
ok("explicit-exit-notify 1" in after, "exit notify 1")
ok("remote vpn.example.com 1195" in read(CLIENT_TEMPLATE), "template remote")
bad = SetSettingsModel(tunnel_address="x", protocol="tcp", ovpn_port=99999, set_new_setting=True)
ok(not change_config(bad), "bad port rejected")

print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
'''


def test_openvpn_pipeline():
    with tempfile.TemporaryDirectory(prefix="ovnode-pki-") as root:
        env = {**os.environ, "OVNODE_OPENVPN_ROOT": root}
        r = subprocess.run(
            [sys.executable, "-c", CHECK_SCRIPT],
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )
        # Surface child output for debugging.
        print(r.stdout)
        if r.stderr:
            print(r.stderr[-2000:])
        assert r.returncode == 0, f"pipeline subprocess failed (rc={r.returncode})"
