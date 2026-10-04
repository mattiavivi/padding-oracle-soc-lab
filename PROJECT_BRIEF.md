# Project Brief: Padding Oracle SOC Lab

> Generato: 2026-10-03 — commit `80982df` — branch `master`
> Scopo: report sintetico da incollare in LLM esterno (ChatGPT/Claude) senza dare repo completo

## 1. Cosa fa (TL;DR)
Laboratorio containerizzato didattico e di ricerca che unisce Crittografia Applicata (Attacco Padding Oracle su AES-CBC con side-channel di stato e timing) e Detection Engineering / SOC (raccolta telemetria ad alte prestazioni via HTTP/SQLite WAL, motori di detection statistica con Sarle Bimodality Coefficient, WAF L7 inline/zero-touch e risposta attiva SOAR a circuito chiuso).

## 2. Tech Stack
- Language/Runtime: Python 3.11+ / 3.12 / 3.13 (gestito con `uv`)
- Web Framework: Flask 3.0+
- Cryptography: `pycryptodome` (AES-CBC, PKCS#7, HMAC-SHA256, Encrypt-then-MAC vs MAC-then-Encrypt)
- SIEM / Storage: SQLite (WAL mode, multi-thread, in-memory buffers + cold JSONL)
- Frontend / Visualization: Vanilla JS, `vis-network.js` (topologia di rete SOC interattiva)
- Infra & Container: Docker, Docker Compose, tmpfs RAM volumes per log ad alta velocità
- Key deps: `flask`, `pycryptodome`, `requests`, `docker`, `pytest`

## 3. Comandi (copia-incolla)
- Setup & Avvio base (victim + soc + soc-ui): `./start.sh up`
- Avvio varianti victim: `./start.sh up-vuln` | `./start.sh up-partial` | `./start.sh up-fixed`
- Generazione traffico benigno: `./start.sh start-benign`
- Esecuzione attacco Padding Oracle: `./start.sh run-attack` (oppure con IP rotation / timing mode: `python attacker/attack.py --target http://localhost:18080 --mode timing --ip-mode per-query`)
- Crypto Workbench interattivo: `python control/crypto_workbench.py --token-b64 "<TOKEN>"`
- Test Suite (Pytest): `pytest -v tests/`
- Smoke Test: `./tests/smoke.sh`
- Query / Alert API: `curl -s http://localhost:18090/alerts` | `curl -s http://localhost:18090/metrics`
- Dashboard UI: Web browser su `http://localhost:18091`

## 4. Struttura Progetto (da ls completo)
```
├── attacker/
│   └── attack.py          → Exploit padding oracle (state/timing oracle, evasion, IP rotation, blending)
├── benign/
│   └── benign_client.py   → Generatore di traffico legittimo multi-attore/IP e rumore di fondo
├── common/
│   ├── crypto_utils.py    → Primitive AES-CBC, PKCS#7 padding/unpadding, EtM/MtE, timing measurements
│   ├── event_logger.py    → Client di telemetria standardizzato verso SIEM e file locali
│   └── siem_query.py      → Motore di query/filtro/aggregazione eventi per Threat Hunting
├── control/
│   ├── alert_rules.json   → Regole di detection SIEM (soglie bimodality, IQR, error rate)
│   ├── crypto_workbench.py→ CLI tool per decifrare e manipolare token CBC a scopo didattico
│   └── waf_policy.json    → Regole preventive L7 WAF (sliding-window, failure rate, consecutive errors)
├── docs/
│   ├── architecture.md    → Architettura del sistema e flussi dati
│   ├── commands.md        → Guida comandi operativi
│   ├── decisions/         → Architecture Decision Records (ADR-001 a ADR-007)
│   ├── detection_engineering_methodology.md → Metodologia di detection e calibrazione soglie
│   ├── paper/             → Paper accademico LaTeX e documentazione formale
│   └── ui.md              → Specifiche della dashboard web
├── runtime-logs/          → Directory volume condivisa per SQLite WAL (`siem_events.db`) e JSONL
├── schemas/
│   └── event_schema.json  → JSON schema della telemetria scambiata tra nodi
├── soc/
│   ├── collector.py       → Server SIEM/SOAR (ingestion API, SQLite indexing, Sarle BC engine, active auto-ban)
│   ├── dashboard.py       → Web UI Flask + Docker API integration + visualizzazione topologia di rete
│   └── static/            → Asset web (`vis-network.min.js`)
├── tests/                 → Test unitari, di integrazione e scenari end-to-end (Pytest)
├── victim/
│   └── app.py             → Web service AES-CBC vulnerabile/parziale/patchato con Fast-Path Inline WAF
├── docker-compose.yml     → Definizione topologia container e mapping porte
├── pyproject.toml         → Metadata del progetto e dipendenze Python
└── start.sh               → Script di orchestrazione CLI del laboratorio
```

## 5. Architettura & Flussi Principali
- **Pattern**: Architettura a microservizi containerizzati con piano dati (Victim, Attacker, Benign) e piano di controllo/monitoraggio (SIEM Collector, SOAR, Dashboard Web).
- **Flusso Crittografico & Side-Channel**:
  1. `victim` espone `/decrypt` ed esegue `verify_and_extract()`. Misura il tempo al nanosecondo (`crypto_processing_time_ns`), isolando l'elaborazione crittografica dalla latenza HTTP di rete ([ADR-002](file:///home/sysadmin/test/padding-oracle-soc-lab/docs/decisions/ADR-002-crypto-processing-timing-and-finite-sample-bimodality.md)).
  2. Modalità `vuln`: restituisce errore 200/400 esplicito ("Invalid padding" vs "Invalid MAC").
  3. Modalità `partial`: restituisce 403 generico per entrambi gli errori, ma con timing side-channel (unpad fallito ritorna prima del check MAC).
  4. Modalità `fixed`: implementa Encrypt-then-MAC (EtM) o constant-time processing.
- **Flusso Telemetria & SIEM / SOAR**:
  1. Ogni operazione emette un evento strutturato (`schemas/event_schema.json`) verso il `soc` Collector (`POST /api/v1/events`).
  2. Il Collector indicizza gli eventi in SQLite WAL (`siem_events.db`).
  3. Il Detection Engine calcola statistiche per IP/Endpoint: Sarle Bimodality Coefficient (BC), IQR, e Failure Rate.
  4. Quando l'indice di anomalia supera la soglia, il SOAR attiva la mitigazione automatica invocando `POST /waf/block_ip` su `victim` con TTL di ban ([ADR-003](file:///home/sysadmin/test/padding-oracle-soc-lab/docs/decisions/ADR-003-closed-loop-soar-active-waf-mitigation.md)).
- **Inline WAF L7 Zero-Touch**:
  - `victim` include un motore WAF sliding-window che blocca preventivamente (HTTP 429) anomalie su singoli endpoint prima dell'intervento del SIEM ([ADR-006](file:///home/sysadmin/test/padding-oracle-soc-lab/docs/decisions/ADR-006-universal-l7-zero-touch-waf-and-scoped-hunting.md), [ADR-007](file:///home/sysadmin/test/padding-oracle-soc-lab/docs/decisions/ADR-007-endpoint-scoped-siem-rules.md)).

## 6. Infrastruttura & Deploy
- **Ambiente Locale**: Docker Compose gestisce i nodi `victim`, `soc`, `soc-ui`, `attacker`, `benign`.
- **Performance I/O**: Volume `ram-logs` montato su tmpfs (RAM 512M) per evitare bottleneck di scrittura disco durante burst di attacchi.
- **Porte Esposte**:
  - Victim API: `18080` (HTTP)
  - SOC Collector SIEM: `18090` (HTTP API)
  - SOC Web UI Dashboard: `18091` (HTTP Web App)
- **Persistenza & Storage**: SQLite con WAL mode e buffer di memoria concorrente protetto da threading locks.

## 7. Convenzioni Codice (Esempio Reale)
```python
# victim/app.py — Gestione misurazione crittografica e telemetria
t_start = time.perf_counter_ns()
status_code, err_msg, plaintext = verify_and_extract(token_bytes, MODE)
t_end = time.perf_counter_ns()
crypto_processing_time_ns = t_end - t_start

# Telemetria verso Collector SIEM
emit_event(
    event_type="crypto_decrypt",
    src_ip=client_ip,
    endpoint=request.path,
    status_code=status_code,
    crypto_processing_time_ns=crypto_processing_time_ns,
    error_reason=err_msg if status_code != 200 else None,
)
```
- **Stile**: Python tipizzato, conformità PEP8/ruff, nomi espliciti e costanti chiare.
- **Gestione Errori**: Logging strutturato con status code HTTP, payload JSON con chiavi standard `{"ok": bool, ...}`.
- **Testing**: Test pytest parametrizzati per detection, WAF, hunting e scenari di exploit.

## 8. Boundaries (Cosa NON fare)
- **Always**:
  - Garantire l'isolamento della telemetria autoritativa del server ([ADR-005](file:///home/sysadmin/test/padding-oracle-soc-lab/docs/decisions/ADR-005-authoritative-server-telemetry-isolation.md)).
  - Misurare solo il tempo effettivo di computazione crittografica `crypto_processing_time_ns`, escludendo i tempi di parsing HTTP e rete.
  - Verificare che le regole WAF/SIEM supportino la scoped detection per endpoint per evitare falsi positivi.
- **Ask first**:
  - Modifiche alla firma degli eventi telemetrici in `schemas/event_schema.json`.
  - Modifiche strutturali ai formati dei token o alla logica di derivazione chiavi.
- **Never**:
  - Introdurre chiamate bloccanti sincrone nel percorso di risposta del victim per inviare log al SIEM.
  - Eseguire comandi Docker distruttivi globali (`docker system prune -a`) durante le pulizie di routine del lab.

## 9. Stato Attuale & Rischi
- **Fatto**:
  - Implementazione completa exploit padding oracle su AES-CBC (oracolo di stato e timing).
  - SIEM collector con SQLite WAL e motore statistico di detection (Sarle Bimodality, IQR).
  - WAF inline applicativo L7 zero-touch con rate limiting, continuous error check e dynamic IP ban.
  - Dashboard SOC Web interattiva con topologia Vis.js, gestione regole SIEM/WAF e tail log in tempo reale.
  - Documentazione formale completa con 7 ADR e paper scientifico in LaTeX.
- **WIP / In corso**:
  - Calibrazione dinamica delle soglie di telemetria per scenari con IP rotation per-query e blend noise avanzato.
- **Rischi / Debito Tecnico**:
  - Carico computazionale del motore di correlazione statistica su campioni di eventi molto grandi in ambienti a singola CPU.
  - Possibili falsi positivi su bimodality statistica quando il numero di campioni analizzati è estremamente ridotto (gestito tramite campioni minimi e correzione Sarle).

## 10. Per LLM Esterno — Prompt Copy-Paste

> Copia da qui in ChatGPT:
> ---
> Questo è il mio progetto (vedi brief sopra). Stack: Python 3.12, Flask, PyCryptodome, SQLite WAL, Docker Compose. Architettura: Laboratorio di sicurezza applicata con server AES-CBC vulnerabile a Padding Oracle, SIEM Collector con detection statistica (Sarle Bimodality / IQR) e Inline WAF L7 / SOAR attivo.
> 
> Voglio chiederti: [INSERISCI DOMANDA QUI — es. "Come ottimizzeresti l'algoritmo di detection del Sarle Bimodality Coefficient per dataset ad alta frequenza?" / "Consigli per migliorare la resilienza del WAF contro attacchi con IP rotation per-query?"]
> 
> Vincoli: Nessun lock sincrono sul path critico di decrypt, telemetria server-side autoritativa, retrocompatibilità con gli ADR esistenti.
> Rispondi con: trade-off, alternativa consigliata e snippet di codice Python pronto all'uso compatibile con lo stack del progetto.
> ---

---
*Footer: generato da `/project-brief` — rigenera con `/project-brief` dopo cambi architetturali.*
