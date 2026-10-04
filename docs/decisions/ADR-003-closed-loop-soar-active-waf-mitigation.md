# ADR-003: Closed-Loop SOAR Active Response & Auto-Expiring WAF Blacklist

## Status
Accepted

## Date
2026-08-28

## Context
The security lab previously operated as a passive SIEM: the SOC collector aggregated logs and detected attacks, but mitigation required manual intervention via the web dashboard. To demonstrate modern automated Security Orchestration, Automation, and Response (SOAR) workflows, the detection engine needed the capability to actively neutralize in-progress cryptographic exploits.

## Decision
1. **Decoupled Data Plane & Control Plane**:
   - **Data Plane (Victim WAF)**: In-line fast-path evaluation (`_check_waf_block()`) returning HTTP 429 before invoking AES-CBC decryption primitives.
   - **Control Plane (SOC Collector SOAR)**: When correlation rules exceed confidence thresholds ($\ge 0.95$), the collector issues an asynchronous mitigation request to `POST /waf/block_ip`.
2. **TTL-Aware Auto-Expiring Blacklist (`WafBlockList`)**:
   Implement a thread-safe, TTL-aware IP blocking table in `victim/app.py` that automatically expires bans (default: 120 seconds), avoiding memory leaks and allowing automatic test environment recovery.

## Alternatives Considered

### Static Permanent IP Blacklist
- Pros: Simple set structure (`set[str]`).
- Cons: Requires manual reset via API or container reboot between test iterations; causes stale state.
- Rejected: Poor operator and student experience during live demos.

### Inline Synchronous WAF Inspection in Collector
- Pros: Centralized inspection logic.
- Cons: Puts collector in the critical path of every incoming victim request (introducing a single point of failure and proxy latency).
- Rejected: Violates microservice separation and adds latency overhead.

## Consequences
- Live demonstration capability: attackers decrying ciphertext blocks are actively halted mid-attack with HTTP 429.
- SOAR actions are tracked as structured mitigation evidence in generated alerts.
- Automatic recovery post-ban via non-blocking TTL expiration.
