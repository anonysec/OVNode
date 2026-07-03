#!/bin/bash
set -euo pipefail

# Never run from inside a directory that may be deleted during reinstall.
cd /tmp

APP_NAME="ov-node"
INSTALL_DIR="/opt/$APP_NAME"
# OVNode is now a standalone repository with node files at repo root.
REPO="anonysec/OVNode"

YELLOW="\033[1;33m"
GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"

echo -e "${YELLOW}Updating system...${NC}"
apt update -y
apt install -y python3 python3-full python3-venv wget curl git ca-certificates build-essential

echo -e "${YELLOW}Installing uv...${NC}"
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:/root/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
    echo -e "${RED}uv install failed or uv is not in PATH.${NC}"
    exit 1
fi

echo -e "${YELLOW}Downloading source...${NC}"
LATEST_URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tarball_url"' | cut -d '"' -f 4 || true)
if [ -z "${LATEST_URL:-}" ]; then
    LATEST_URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
fi

rm -rf /tmp/ov-node-extract /tmp/ov-node-source.tar.gz
mkdir -p /tmp/ov-node-extract
curl -L --fail -o /tmp/ov-node-source.tar.gz "$LATEST_URL"
tar -xzf /tmp/ov-node-source.tar.gz -C /tmp/ov-node-extract

SRC_DIR=$(find /tmp/ov-node-extract -mindepth 1 -maxdepth 1 -type d | head -n 1)
if [ -z "$SRC_DIR" ] || [ ! -d "$SRC_DIR" ]; then
    echo -e "${RED}Could not find extracted OVNode source.${NC}"
    exit 1
fi

echo -e "${YELLOW}Installing into $INSTALL_DIR...${NC}"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -a "$SRC_DIR"/. "$INSTALL_DIR"/
rm -rf /tmp/ov-node-extract /tmp/ov-node-source.tar.gz

cd "$INSTALL_DIR"

echo -e "${YELLOW}Installing Python dependencies...${NC}"
uv sync

echo -e "${YELLOW}Launching OV-Node installer...${NC}"
uv run python installer.py

echo -e "${GREEN}Done.${NC}"
