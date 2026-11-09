# Changes – Exposure check

## 0.2.0 – 2026-11-09

Outside view, first part: the router.

### New
- Optional (off by default): the node asks the router via UPnP for its active port forwards and shows them as "Reachable from the internet?", with a level (*likely* when the target listens there, otherwise *unknown*) and a classification (*expected* or *unexpected*). New and recently gone forwards are marked.
- "Expected ports": ports you deliberately open show up as expected.
- The address of the router can be entered by hand; it must be an IP address on a private network.
- Local API: `GET /api/exposure/overview`, `GET|POST /api/exposure/expected`, `DELETE /api/exposure/expected/{proto}/{port}`; settings and status extended with UPnP.
- Note: this only shows what the router knows. "Likely" is no confirmation from outside.

## 0.1.0 – 2026-11-09

First version (inside view).

### New
- Shows which ports the node itself listens on and which module owns the port (a port without an owner shows up as "foreign program").
- Optional: check known devices of the IPAM subnets for common ports using a TCP connect (private networks only, switchable per subnet).
- Local API under `/api/exposure`.
