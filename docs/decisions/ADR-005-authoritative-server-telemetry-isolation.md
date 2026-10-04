# ADR-005: Authoritative Server Telemetry Isolation in SIEM (Deduplicazione Client-Server)

## Status
Accepted

## Date
2026-09-26

## Context
Nel laboratorio coesistono tre attori che emettono eventi strutturati tramite `common.event_logger`:
1. `victim`: il server target / WAF che registra ogni richiesta HTTP in ingresso (`service = "victim"`).
2. `attacker`: il modulo exploit che registra ciascun probe inviato e lo stato interno dell'attacco (`service = "attacker"`).
3. `benign`: il client di simulazione traffico legittimo (`service = "benign"`).

In precedenza, il modulo SIEM e Threat Hunting (`soc/collector.py` e `soc/dashboard.py`) leggeva indiscriminatamente tutti i file `.jsonl` memorizzati in `/logs` (`victim.jsonl`, `attacker.jsonl`, `benign.jsonl`).
Quando l'attaccante operava in modalità *Rotazione Ephemera Continua* (`1 IP = 1 Query`, `--ip-mode per-query`), ogni singola richiesta HTTP generava due record associati al medesimo indirizzo IP sorgente:
- Un evento client da `attacker.jsonl` (latenza ~9ms misurata dal client).
- Un evento server da `victim.jsonl` (latenza ~0.3ms misurata su Flask).

Di conseguenza, nel Threat Hunting Explorer e nel motore di allarmi SOC, per ogni singolo probe l'analista osservava 2 richieste e 2 errori, raddoppiando artificialmente le metriche e anticipando impropriamente il trigger delle soglie di allerta.

## Decision
1. **Isolamento della Telemetria Difensiva (`_is_victim_telemetry`)**:
   Tutti i moduli analitici difensivi (Threat Hunting `/hunting/explore`, query SIEM `/hunting/query`, Live Backtest `/hunting/backtest`, allarmi `_build_alerts` e reportistica forense `/forensics/report`) processano **esclusivamente gli eventi dove `service == "victim"`**.
2. **Preservazione dei Log Client per Scopi Didattici**:
   I file `attacker.jsonl` e `benign.jsonl` continuano a essere scritti:
   - `attacker.jsonl` alimenta la visualizzazione in tempo reale dei byte decifrati (`event_type == "attack_progress"`) nella UI Red Team e il calcolo dell'MTTD.
   - Viene preservata l'estrazione degli IP avversari (`attacker_ips`) per evidenziare le etichette didattiche di laboratorio (`👁️ Info Lab / Ground-Truth`).
3. **Riavvio del Processo Flask del SOC (`soc` / `soc-ui`)**:
   Poiché l'applicazione Flask carica i moduli in RAM all'avvio del container Docker, per rendere effettivo il filtraggio in ambiente live è necessario il riavvio del container (`docker restart soc soc-ui`).

## Alternatives Considered

### Fusione/Deduplicazione Euristica Client-Server
- **Idea**: Effettuare una deduplicazione unendo le coppie `(src_ip, ts)` o correlando l'evento attacker con quello victim.
- **Rifiutata**: Inutile complessità algoritmica. Nella realtà operativa di un SOC aziendale, il team difensivo non riceve mai la telemetria interna delle macchine degli aggressori, ma analizza unicamente i log generati dal reverse proxy, dal WAF e dal server applicativo. I log della vittima sono già completi di tutte le feature necessarie (IP, endpoint, status code, latenze, tempo crittografico nanosecondi, lunghezza ciphertext e tipo errore).

## Consequences
- **Risoluzione Completa del Raddoppio**: Con 1 IP = 1 Query, il SIEM riporta esattamente $1$ evento, $1$ richiesta di decifratura e $1$ errore, con la latenza reale del server (~0.3ms).
- **Allineamento Soglie Allarmi**: Gli allarmi SIEM scattano al raggiungimento esatto delle soglie di probe configurate (es. 25 richieste effettive, anziché 13 raddoppiate).
- **Realismo Accademico**: L'architettura rispecchia fedelmente un'infrastruttura SOC reale di produzione, mantenendo separate le funzioni di ground-truth didattica da quelle di threat detection.
