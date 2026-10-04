# ADR-004: Single-Container Victim with Dynamic Mode Switch

## Status
Accepted

## Date
2026-08-28

## Context
Early lab designs considered running three separate victim containers on distinct host ports (`victim-vuln` on 18080, `victim-partial` on 18081, `victim-fixed` on 18082). This caused port sprawl, required complex compose profiles, and prevented seamless live demonstrations comparing vulnerable vs. mitigated behavior against the same target URL.

## Decision
Consolidate into a single `victim` container service (port 18080) exposing a dynamic runtime configuration endpoint (`POST /mode` and `POST /api/v1/mode`):
- `vuln`: Classic Padding Oracle (differentiates padding errors via HTTP 500 vs. integrity errors via HTTP 403).
- `partial`: Timing Side-Channel Oracle (uniform HTTP 403 status, with simulated non-constant differential timing: ~30ms vs. ~5ms).
- `fixed`: Constant-Time Mitigated Mode (uniform HTTP 403 response with constant timing execution).

Helper scripts (`scenario.sh up-vuln`, `up-partial`, `up-fixed`) and the interactive web UI trigger this endpoint dynamically without restarting containers.

## Alternatives Considered

### Multi-Container Victim Architecture (3 separate services)
- Pros: Strict container isolation.
- Cons: Triple the container footprint, port conflicts, requires reconfiguring attacker scripts for each mode.
- Rejected: Clunky user experience during educational presentations.

## Consequences
- Single endpoint URL (`http://victim:8080` or `http://localhost:18080`) throughout all testing scenarios.
- Instantaneous switching between attack demonstration and defense demonstration.
- Cleaner Docker Compose manifest and reduced resource utilization.
