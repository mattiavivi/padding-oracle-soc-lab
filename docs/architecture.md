# Architettura del Laboratorio

## Obiettivo
Laboratorio containerizzato didattico per lo studio, l'exploit e la detection di:
- **Padding Oracle Attack su AES-CBC** (oracolo classico di stato e timing side-channel).
- **SOC / SIEM Layer**: raccolta telemetria ad alte prestazioni (HTTP Ingestion + SQLite WAL + cold JSONL), detection statistica avanzata e risposta attiva SOAR.

## Servizi e Container

| Servizio | Ruolo | Porta host | Note |
|---|---|---|---|
| `victim` | Server AES-CBC con switch dinamico `POST /mode` (`vuln`, `partial`, `fixed`) + Inline WAF | `18080` | [ADR-004](decisions/ADR-004-single-container-victim-with-dynamic-mode-switch.md) |
| `attacker` | Script exploit Padding Oracle byte-by-byte su AES-CBC (`--mode vuln\|timing`) | n/a | Container one-shot o daemon |
| `benign` | Generatore di traffico multi-IP e simulazione client legittimo | n/a | Gestito via CLI o UI |
| `soc` | Collector SIEM/SOAR: ingestion HTTP `/api/v1/events`, SQLite WAL, detection engine, `/alerts`, `/metrics` | `18090` | [ADR-001](decisions/ADR-001-telemetry-ingestion-pipeline.md) |
| `soc-ui` | Dashboard web Flask interattiva con visualizzazione topologica `vis-network.js` | `18091` | Gestione nodi, log tail e WAF |

## Flusso Dati & Telemetria

```
┌─────────────┐        ┌─────────────┐
│  Attacker   │        │   Benign    │
└──────┬──────┘        └──────┬──────┘
       │ HTTP /decrypt        │ HTTP /decrypt
       ▼                      ▼
┌────────────────────────────────────┐
│      Victim (AES-CBC Server)       │ ──► [Fast-Path Inline WAF Block 429]
│  - crypto_processing_time_ns       │
│  - Dynamic Mode: vuln/partial/fixed│
└─────────────────┬──────────────────┘
                  │ Ingestion Event Stream (HTTP POST / Async Queue)
                  ▼
┌────────────────────────────────────┐
│      SOC Collector (SIEM/SOAR)     │
│  - Storage: SQLite WAL + JSONL     │
│  - Detection: Sarle BC + IQR       │
│  - SOAR: Active WAF Auto-Mitigate  │ ──► [Trigger POST /waf/block_ip (TTL)]
└─────────────────┬──────────────────┘
                  │ Metrics / Alerts / Topology
                  ▼
┌────────────────────────────────────┐
│    SOC Dashboard Web UI (:18091)   │
└────────────────────────────────────┘
```

1. **Esecuzione & Timing Crittografico**: Il victim misura `crypto_processing_time_ns` con precisione al nanosecondo attorno a `verify_and_extract()`, separando il calcolo crittografico dall'overhead web/rete ([ADR-002](decisions/ADR-002-crypto-processing-timing-and-finite-sample-bimodality.md)).
2. **Ingestion Asincrona**: I nodi inviano telemetria al Collector via HTTP o cold-storage JSONL senza bloccare le risposte crittografiche ([ADR-001](decisions/ADR-001-telemetry-ingestion-pipeline.md)).
3. **Detection Engine**: Il collector analizza la bimodalità di Sarle corretta per campioni finiti e il failure-rate per identificare anomalie.
4. **Circuito Chiuso SOAR**: Al superamento della confidenza di attacco, il collector blocca dinamicamente l'IP sulla blacklist del victim con TTL temporale automatico ([ADR-003](decisions/ADR-003-closed-loop-soar-active-waf-mitigation.md)).

## Architecture Decision Records (ADRs)
Tutte le decisioni architetturali rilevanti sono tracciate in [`docs/decisions/`](decisions/README.md).

