# Contributing

Thanks for considering it. This is the node agent a panel manages; it runs as root
and drives OpenVPN, so a change here can take a customer's VPN down. The bar
reflects that.

## Getting set up

You need Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/anonysec/OVNode.git
cd OVNode
uv sync --extra dev
```

The suite needs `openvpn` and `easy-rsa` present — the PKI pipeline test drives
them for real rather than stubbing them:

```bash
sudo apt-get install -y openvpn easy-rsa iptables iproute2 logrotate
```

## Before you open a pull request

```bash
.venv/bin/python -m pytest tests/ -q          # 343 passed, 1 skipped
.venv/bin/ruff check core tests
.venv/bin/ruff format --check core tests
bash -n install.sh manager.sh scripts/lib/*.sh
```

All four must pass; CI runs the same suite.

**Tests that need root are gated, not deleted.** The suite runs unprivileged in CI
and as root locally, so anything asserting ownership or an unreadable file uses
`skipif` on the effective uid. Gate new ones the same way — a test that passes as
root and fails in CI is worse than no test.

## House rules

- **Comments must earn their place.** Existing ones explain a non-obvious tradeoff
  or a bug that was actually hit. Match that; do not narrate what the code says.
- **`scripts/lib/*.sh` is the only definition of a shared shell helper.**
  `install.sh` and `manager.sh` source it. Do not copy a function into either.
- **A read-only command that cannot read `.env` must say so.** Never fall back to
  a default that looks like data — plausible values you failed to read are worse
  than an error.
- **Never print a private key or a full config.** Key material stays `0600`.
- Treat every request-supplied path as hostile: resolve it and confirm it stays
  inside the intended root before any read, write, or delete.
- The installer takes three flags (`-y`, `--docker`, `-h`); everything else is an
  `OVN_*` variable. Older spellings still work but warn, and are being removed.

## Commits

Small, focused commits whose message says *why* — the diff already says what. One
change per commit where you can.

## Security

Do not open a public issue for a vulnerability. See [`SECURITY.md`](../SECURITY.md).

## Conduct

Assume good faith and be straightforward. Technical disagreement is fine and
useful; personal remarks are not, and maintainers may close anything that turns
into the latter.

## License

Contributions are accepted under the project's MIT license.
