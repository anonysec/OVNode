# Iranian ISP Compatibility Matrix

Tested on VPS `23.88.54.254` (OVNode v2.0.3, OpenVPN 2.7.0).

| Protocol / Port | MCI | MTN (Irancell) |
|---|---|---|
| UDP 443 | ✅ works | ❌ blocked |
| TCP 443 | ❌ blocked | ✅ works |
| UDP 8443 | ✅ works | ✅ works |
| TCP 8443 | ❌ blocked | ✅ works |

## Summary

- **MCI** blocks all TCP to this IP (both 443 and 8443). Only UDP works.
- **MTN** blocks UDP 443 specifically but allows UDP 8443 and all TCP.
- **UDP 8443** is the only combination that works on **both** ISPs.

## Recommendations

- **MCI users:** UDP on any port (443 or 8443).
- **MTN users:** TCP on any port, or UDP on 8443. Avoid UDP 443.
- **Universal (both ISPs):** UDP 8443.
- **Dual-protocol .ovpn (UDP 443 + TCP 443):** Works on both — client tries UDP first (MCI), falls back to TCP (MTN).

## Notes

- Results may vary by region and time. Iranian GFW rules change frequently.
- TCP mode is ~20-40% slower than UDP due to TCP-over-TCP.
- Port 8443 is less monitored than 443 but may be blocked in some regions.
- These results are for this specific VPS IP. A different server IP may have different blocking patterns.