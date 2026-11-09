# Changes – Exposure check

## 0.3.0 – 2026-11-09

Observable day to day: history, notifications, dashboard card, metrics, export.

### New
- History: new and gone port forwards of the router and new or gone listening ports, newest first. The first recording of an address creates no entries. Retention 30, 90 (default), 365 days or unlimited.
- Notifications over your configured channels: for a new *unexpected* forward (on by default), optionally for a new *expected* forward and for a new listening port. Several changes of one run arrive as one notification; the same change is reported at most once every 24 hours, and a restart does not repeat anything.
- Dashboard card and metrics at `/api/metrics` (`node64_exposure_*`); both read the database only.
- Export and import of the configuration (settings and expected ports; the subnet selection is not part of it). The import checks everything first and changes nothing on an error.
- Local API: `GET /api/exposure/history`; the settings know `keep_days`, `notify_unexpected`, `notify_new` and `notify_listen`.

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
