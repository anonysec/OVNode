# Iranian ISP compatibility

Tested with OVNode 2.0.0 and OpenVPN 2.7.0. The matrix is about which
transport each ISP lets through, not about the panel or user accounts.

## Matrix

| ISP | UDP/443 | TCP/443 | UDP/1194 | Notes |
| --- | --- | --- | --- | --- |
| MCI (Hamrah Aval) | works | often filtered | works | UDP is the reliable path |
| MTN Irancell | blocked on some plans | works | blocked on some plans | TCP is the reliable path |
| Fixed broadband (TCI, etc.) | usually works | works | usually works | Either transport |

Filtering changes over time and by province. Treat the table as a starting
point, not a guarantee.

## Recommended setup: one node, both protocols

Install with `Proto=both` (panel: protocol **Both**):

```bash
Proto=both VpnPorts=443 bash install.sh -y
```

The node runs one OpenVPN process per protocol on port 443:

- UDP and TCP each have their own config, status, PID, log and management
  socket under `/var/lib/<instance>/openvpn/server/<proto>/`.
- The instance owns a `/23`; UDP uses the first `/24`, TCP the second.
- Every generated profile carries a `<connection>` block for UDP and one for
  TCP, tried in order. The same `.ovpn` therefore works on MCI (UDP) and MTN
  (TCP) without a second node or a hand-edited template.

If a specific ISP blocks port 443 entirely, add another port with
`VpnPorts=443,8443` (or set extra ports from the panel). Every port gets its
own connection block per protocol.

## Two single-protocol nodes

If you prefer separate nodes, register one UDP node and one TCP node and hand
out the profile that matches the user's ISP. Do **not** merge remotes from
two nodes into one profile: certificates are per node, so a fallback to the
other node fails TLS verification.

## Diagnostics

- `ovnode status` shows both children and their management sockets.
- `journalctl -u <instance>` shows each OpenVPN process's log lines.
- A profile that connects but passes no traffic usually means the port is
  reachable but the protocol is throttled; switch the client to the other
  `<connection>` block.
- TCP through a filtering middlebox can look connected but stall; lower MSS
  (`Mssfix` 1200–1350 in the panel's OpenVPN tuning) often fixes it.
