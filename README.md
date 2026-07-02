# OVNode

OVNode is the OpenVPN node-side service used by OVManager. It exposes authenticated sync APIs and installs OpenVPN hooks for traffic accounting, multi-login enforcement, and per-user disconnect.

## Features

- OpenVPN user/config generation
- Per-config max-login enforcement
- Stale session marker cleanup
- Traffic usage reporting
- Per-user disconnect via OpenVPN management socket
- Health/status endpoint for OVManager

## Components

- `node/` — FastAPI node service, OpenVPN scripts, installer

## License

Private project source published by repository owner.
