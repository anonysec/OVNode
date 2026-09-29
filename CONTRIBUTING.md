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
3. Shell changes: `bash -n` clean; installer changes must keep the exit
   codes and the all-human-output-on-stderr contract intact (see
   `install.sh help`).
4. Never commit secrets (`.env`, `/etc/openvpn` contents, `*.db`).

## Questions?

**Discussions** for usage questions; **issues** for bugs with reproduction
steps (version, logs, expected vs actual).

## Release freeze

Changes land on `main` through a pull request, and the required checks must
pass before it merges — the same gate the sibling OVManager repo uses. There
is no release freeze: versions are bumped and tagged from `main` as part of
each release (see CHANGELOG for the shipped history).
