# OVNode

OpenVPN node agent for [OVManager](https://github.com/anonysec/OVManager). Manages OpenVPN server, PKI, user configs, and multi-login enforcement.

## Install

```bash
bash <(curl -sSL https://anonysec.github.io/OVNode/install.sh)
```

With options:

```bash
bash <(curl -sSL URL) -- --port 2083 --api-key YOUR_KEY --vpn-port 1194
```

## Update / Uninstall

```bash
# Update
bash <(curl -sSL URL) update

# Uninstall
bash <(curl -sSL URL) uninstall
```

## Docker

```bash
bash <(curl -sSL URL) --docker
```

## Manual Install

```bash
git clone https://github.com/anonysec/OVNode.git /opt/ovnode
cd /opt/ovnode
cp .env.example .env  # edit with your settings
pip install uv && uv sync
uv run main.py
```

## License

MIT
