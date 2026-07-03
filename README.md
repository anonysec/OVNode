# OVNode

OVNode is the OpenVPN node-side service used by OVManager. It exposes authenticated sync APIs and installs OpenVPN hooks for traffic accounting, multi-login enforcement, stale marker cleanup, and per-user disconnect.

## Features

- OpenVPN user/config generation
- Per-config max-login enforcement
- Automatic stale active-session marker cleanup
- Traffic usage reporting with per-session counters
- Per-user disconnect via local OpenVPN management socket
- Health/status/version endpoint for OVManager

## Project structure

- `core/` — FastAPI app, routers, OpenVPN services and scripts
- `install.sh` / `installer.py` — installer entrypoints
- `data/` — runtime data directory placeholder

## Notes

Do not commit `.env`, runtime databases, logs, or generated virtualenv directories.
