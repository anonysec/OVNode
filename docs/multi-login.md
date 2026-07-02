# Multi-Login (per-config simultaneous connection limit)

This node enforces ov-panel's **Max Logins** setting — how many devices may connect
with the same config (certificate) at the same time.

- `max_logins = 1` → single login (default).
- `max_logins = N` → up to N simultaneous devices.
- `max_logins = 0` → unlimited.

**Policy: when the limit is reached, the new connection is rejected** (existing sessions
keep running).

## What was added

| Area | Change |
| --- | --- |
| `core/schema/all_schemas.py` | `User.max_logins` (optional) + new `UserLimit` model. |
| `core/routers/router.py` | `POST /sync/user` and `PUT /sync/user` accept `max_logins`; new `PUT /sync/user/limit`. |
| `core/service/user_managment.py` | `set_user_limit` / `remove_user_limit`; create persists the limit, delete removes it. |
| `core/service/multilogin.py` | Idempotent setup: installs scripts + patches `server.conf`. |
| `core/scripts/ovpanel-client-connect.sh` | Counts live sessions per CN (from the status log) and rejects over-limit connections. |
| `core/scripts/ovpanel-client-disconnect.sh` | No-op stub (kept so the `client-disconnect` directive is valid). |
| `core/app.py` | Runs `ensure_multilogin_setup()` on startup. |

## How it works

1. The panel sends `max_logins` when creating/updating a user, or via
   `PUT /sync/user/limit`. The node writes it to `/etc/openvpn/limits/<name>`.
2. On node startup, `ensure_multilogin_setup()` (idempotently):
   - copies the enforcement scripts to `/etc/openvpn/scripts/`,
   - ensures `server.conf` has `duplicate-cn`, `script-security 2`,
     `client-connect` / `client-disconnect`, and a `status` log directive,
   - restarts OpenVPN only if `server.conf` actually changed.
3. On each new connection OpenVPN runs `client-connect`, which reads the limit and counts
   the certificate's **current sessions from the status log**
   (`/var/log/openvpn-status.log`). Because the hook runs before the new client is added
   to the list, that count is the number of already-established sessions, so it rejects
   the connection when `current >= limit`.

### Why count from the status log?

ov-node restarts the OpenVPN service on activate/deactivate and on settings changes. A
persistent per-CN counter would drift across those restarts (disconnect hooks aren't
guaranteed to fire on shutdown) and could wrongly block clients. Reading live sessions
from the status log is the source of truth and is immune to restarts.

### Why `duplicate-cn`?

OpenVPN normally allows only one session per certificate. To permit N devices on one
config we enable `duplicate-cn` (which alone means *unlimited*) and re-impose the exact
cap in the connect script.

### Status log format

The setup ensures `server.conf` has `status-version 3`, which produces the
machine-readable `CLIENT_LIST,<CN>,<real-addr>,...` layout. Both the connection-limit
script and the traffic accounting parse that format; the default (version 1) layout has
no `CLIENT_LIST` prefix and would silently disable both.

### Notes & limitations

- Missing limit file ⇒ default `1` (safety net for pre-existing certs).
- The status log refreshes on an interval (default 5s). Two devices connecting within the
  same refresh window can both be admitted briefly before the count catches up; the limit
  is enforced on subsequent connects. For a hard real-time cap you'd use the OpenVPN
  management interface, which is intentionally avoided here to keep the node simple.
- For existing installs, the setup runs automatically the next time `ov-node` starts
  (e.g. after `Update`/`Restart` in the installer).
