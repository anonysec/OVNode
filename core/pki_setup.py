"""
PKI initialization for OVNode.

Runs once at container startup. If PKI already exists (persisted via Docker
volume), it skips initialization so existing client configs remain valid.
If PKI is missing, creates a fresh CA + server cert + all prerequisites.
"""
import os
import shutil
import subprocess
import logging

logger = logging.getLogger("pki_setup")

# Path constants — must match user_managment.py
EASYRSA_DIR = "/etc/openvpn/server/easy-rsa"
PKI_DIR = "/etc/openvpn/server/pki"
SERVER_CONF = "/etc/openvpn/server/server.conf"
CLIENT_TEMPLATE = "/etc/openvpn/server/client-common.txt"
TLS_KEY = "/etc/openvpn/server/tls.key"
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
SERVER_CERT = os.path.join(PKI_DIR, "issued", "server.crt")
DH_PEM = os.path.join(PKI_DIR, "dh.pem")

REQUIRED_DIRS = [
    "/etc/openvpn/server",
    "/etc/openvpn/clients",
    "/etc/openvpn/ccd",
    "/etc/openvpn/limits",
]


def _setup_easyrsa():
    """Copy easy-rsa toolkit if not already present."""
    if os.path.exists(EASYRSA_DIR) and os.path.exists(os.path.join(EASYRSA_DIR, "easyrsa")):
        return
    os.makedirs(EASYRSA_DIR, exist_ok=True)
    src = "/usr/share/easy-rsa"
    if not os.path.exists(src):
        import subprocess as sp
        r = sp.run(["dpkg", "-L", "easy-rsa"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("/usr/share/easy-rsa/"):
                src = "/usr/share/easy-rsa"
                break
    if os.path.exists(src):
        subprocess.run(["cp", "-r", f"{src}/.", EASYRSA_DIR], check=True)
        os.chmod(os.path.join(EASYRSA_DIR, "easyrsa"), 0o755)


def _easyrsa(*args, timeout=120):
    """Run easyrsa --pki-dir=PKI_DIR with EASYRSA_BATCH=1. Returns True on success."""
    easyrsa_bin = os.path.join(EASYRSA_DIR, "easyrsa")
    if not os.path.exists(easyrsa_bin):
        logger.error("easyrsa not found at %s", easyrsa_bin)
        return False
    try:
        cmd = [easyrsa_bin, f"--pki-dir={PKI_DIR}"] + list(args)
        env = {**os.environ, "EASYRSA_BATCH": "1"}
        subprocess.run(
            cmd,
            cwd=EASYRSA_DIR,
            env=env,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.error("easyrsa %s failed (rc=%d): %s",
                     " ".join(args), e.returncode,
                     e.stderr[-300].decode() if e.stderr else str(e))
        return False
    except Exception as e:
        logger.error("easyrsa %s error: %s", " ".join(args), e)
        return False


def _ensure_dir_tree():
    """Create all PKI subdirectories needed for easyrsa operations."""
    subdirs = [
        "private", "issued", "reqs", "certs_by_serial",
        "index.txt.attrs", "inline/private", "revoked/certs_by_serial",
        "revoked/private", "revoked/reqs", "revoked/issued",
    ]
    for subdir in subdirs:
        os.makedirs(os.path.join(PKI_DIR, subdir), exist_ok=True)
    # Initialize index files
    for fname in ["index.txt", "index.txt.attr", "serial", "serial.old",
                   "crlnumber", "crlnumber.old"]:
        path = os.path.join(PKI_DIR, fname)
        if not os.path.exists(path):
            with open(path, "w") as f:
                if fname == "serial" or fname == "crlnumber":
                    f.write("1000\n")
                else:
                    pass  # empty file


def init_pki():
    """Initialize PKI if it doesn't exist. Safe to call on every startup."""
    for d in REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)

    _setup_easyrsa()

    if os.path.exists(CA_CERT) and os.path.exists(SERVER_CERT):
        logger.info("PKI already exists — skipping initialization.")
        if not os.path.exists(TLS_KEY):
            logger.warning("TLS key missing from existing PKI, generating...")
            subprocess.run(
                ["openvpn", "--genkey", "secret", TLS_KEY],
                check=True, capture_output=True, timeout=30,
            )
            os.chmod(TLS_KEY, 0o600)
            logger.info("TLS key generated and permissions set.")
        _ensure_server_conf()
        _ensure_client_template()
        return

    # If pki dir exists as a Docker mount point it can't be rmdir'd from
    # inside the container. Create the directory structure manually and
    # proceed with CA/cert generation — easyrsa --pki-dir handles the rest.
    if not os.path.exists(PKI_DIR):
        os.makedirs(PKI_DIR, exist_ok=True)

    logger.info("PKI not found — initializing new Certificate Authority at %s", PKI_DIR)
    _ensure_dir_tree()

    # Build CA (non-interactive)
    if not _easyrsa("build-ca", "nopass"):
        logger.error("CA creation failed — check logs above.")
        return
    logger.info("CA certificate created.")

    # Build server cert
    if not _easyrsa("build-server-full", "server", "nopass"):
        logger.error("Server cert creation failed.")
        return
    logger.info("Server certificate created.")

    # Generate DH params
    _easyrsa("gen-dh")
    logger.info("DH parameters generated.")

    # Generate TLS crypt key
    subprocess.run(
        ["openvpn", "--genkey", "secret", TLS_KEY],
        check=True, capture_output=True, timeout=30,
    )
    os.chmod(TLS_KEY, 0o600)
    logger.info("TLS key generated and permissions set.")

    _ensure_server_conf()
    _ensure_client_template()
    logger.info("PKI initialization complete.")


def _ensure_server_conf():
    """Write server.conf if missing."""
    if os.path.exists(SERVER_CONF):
        return
    port = os.environ.get("OPENVPN_PORT", "1194")
    content = f"""port {port}
proto tcp
dev tun
ca {PKI_DIR}/ca.crt
cert {PKI_DIR}/issued/server.crt
key {PKI_DIR}/private/server.key
dh {PKI_DIR}/dh.pem
tls-crypt {TLS_KEY}
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/server/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
auth SHA256
cipher AES-256-GCM
ncp-ciphers AES-256-GCM:AES-128-GCM
user nobody
group nogroup
persist-key
persist-tun
status /etc/openvpn/server/status.log
log-append /etc/openvpn/server/openvpn.log
verb 3
explicit-exit-notify 0
client-config-dir /etc/openvpn/ccd
cd /etc/openvpn/server
duplicate-cn
max-clients 100
"""
    with open(SERVER_CONF, "w") as f:
        f.write(content)
    logger.info("Created server.conf")


def _ensure_client_template():
    """Write client-common.txt if missing."""
    if os.path.exists(CLIENT_TEMPLATE):
        return
    vpn_port = os.environ.get("OPENVPN_PORT", "1194")
    content = f"""client
dev tun
proto tcp
remote 91.107.164.180 {vpn_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
auth SHA256
cipher AES-256-GCM
verb 3
"""
    with open(CLIENT_TEMPLATE, "w") as f:
        f.write(content)
    logger.info("Created client-common.txt")