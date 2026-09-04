# Contributing

Thanks for helping. This project stays small on purpose.

## Ground rules

- **One PR = one concern, < 300 lines.**
- **No new dependencies** without prior discussion.
- **No new features during freeze** — bug, security, test, and docs PRs welcome.
- New sync-API behavior needs a contract test in `tests/test_integration.py`
  and a matching note in `README.md` (the endpoint table).

## Workflow

1. Fork, branch from `main`.
2. `uv sync && uv run pytest -q` green; `ruff check .` clean.
   (`filterwarnings = error` — fix warnings, don't mute them.)
3. Shell changes: `bash -n` clean; installer changes must keep
   `--json` machine output intact (see `install.sh help`).
4. Never commit secrets (`.env`, `/etc/openvpn` contents, `*.db`).

## Questions?

**Discussions** for usage questions; **issues** for bugs with reproduction
steps (version, logs, expected vs actual).
