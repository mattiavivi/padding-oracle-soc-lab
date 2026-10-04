# ADR-001: Telemetry Ingestion Pipeline (HTTP + SQLite WAL + Cold JSONL)

## Status
Accepted

## Date
2026-08-28

## Context
In multi-container scenarios (attacker running high-frequency probing alongside concurrent benign client bursts), telemetry log emission through direct concurrent `open(..., "a")` on shared Docker bind-mounted JSONL files (`runtime-logs/*.jsonl`) caused potential file lock contention, polling latency, and I/O overhead on the SOC collector.
We needed a resilient, high-throughput ingestion mechanism that preserves the educational requirement of zero external heavy dependencies (no Kafka, Elasticsearch, or external DBMS).

## Decision
1. **Collector Ingestion API (`POST /api/v1/events`)**: The SOC collector exposes a lightweight HTTP REST ingestion endpoint.
2. **Asynchronous Non-Blocking Logger**: `common/event_logger.py` uses an internal in-memory queue (`queue.Queue`) and background worker thread to dispatch logs without introducing latency into cryptographic victim endpoints.
3. **Single-Writer Cold Storage**: The SOC collector becomes the sole process writer for persistent JSONL log files.
4. **Embedded SQLite WAL Engine**: Ingested events are indexed and queryable via an embedded SQLite database configured in WAL (`Write-Ahead Logging`) mode.

## Alternatives Considered

### Direct Shared JSONL Files Only (Legacy)
- Pros: Minimal code, no networking logic required.
- Cons: File lock contention under concurrent load, synchronous polling overhead in collector.
- Rejected: Scalability bottleneck during high-rate attack simulations.

### External Message Broker (Redis Streams / NATS / RabbitMQ)
- Pros: Native backpressure, distributed queues, persistent replay streams.
- Cons: Additional infrastructure footprint, increased RAM usage, external Python library dependencies.
- Rejected: Over-engineering for a standalone educational security lab.

## Consequences
- Zero file lock contention between victim, attacker, and benign containers.
- Sub-millisecond logging latency for API handlers.
- Query performance for SIEM aggregations improved significantly via SQLite WAL indices.
- Standard JSONL cold storage preserved for offline inspection and forensics.
