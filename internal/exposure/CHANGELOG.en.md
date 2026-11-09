# Changes – Exposure check

## 0.1.0 – 2026-11-09

First version (inside view).

### New
- Shows which ports the node itself listens on and which module owns the port (a port without an owner shows up as "foreign program").
- Optional: check known devices of the IPAM subnets for common ports using a TCP connect (private networks only, switchable per subnet).
- Local API under `/api/exposure`.
