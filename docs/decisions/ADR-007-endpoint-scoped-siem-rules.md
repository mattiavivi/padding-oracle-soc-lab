# ADR-007: Endpoint-Scoped SIEM Correlation Rules and Scoped SOAR Active Mitigation

## Status
Accepted

## Date
2026-09-26

## Context
Con l'introduzione dell'architettura [ADR-006](file:///home/sysadmin/test/padding-oracle-soc-lab/docs/decisions/ADR-006-universal-l7-zero-touch-waf-and-scoped-hunting.md), il Web Application Firewall (WAF) della vittima è stato evoluto in un filtro Layer 7 Universale e Zero-Touch:
- Le regole WAF operano su specifici endpoint API (`/api/v1/crypto/decrypt`, `/api/v1/auth/login`, `*`).
- Le quarantene applicate (`WafBlockList`) indicizzano tuple `(ip, endpoint)`, garantendo il principio di *Availability-First Defense* (un attacco di credential stuffing su `/login` non causa il diniego di servizio sulle funzionalità crittografiche `/decrypt` per lo stesso IP).

Tuttavia, il motore di correlazione SIEM (`soc/collector.py`) e l'interfaccia di calibrazione delle regole (`soc/dashboard.py`) presentavano ancora tre disallineamenti significativi:
1. **Filtro Hardcoded a `/decrypt` nel SIEM Engine**:
   In `_build_alerts()`, la telemetria difensiva veniva filtrata globalmente tramite `_is_decrypt_event(e)`. Se un attaccante eseguiva scansioni o tentativi di brute force su `/api/v1/auth/login` o altri endpoint applicativi, il SIEM ignorava completamente tali eventi.
2. **Assenza di Scoping per Endpoint nelle Regole SIEM**:
   Le regole di rilevamento (sia predefinite che personalizzate create nel catalogo) non supportavano il campo `endpoint`, impedendo all'analista SOC di calibrare soglie di fail-rate, burst di richieste o bimodalità limitate a determinate API o estese a tutte (`*`).
3. **Mancanza di Isolamento nella Risposta Automatica SOAR**:
   Quando scattava un allarme SIEM, la funzione `_trigger_soar_mitigation` inviava al WAF una richiesta di blocco contenente unicamente `{"ip": ip}`, provocando un ban globale su tutti gli endpoint invece di un blocco chirurgico sulla tupla `(ip, endpoint)` rilevata.
4. **Asimmetria Grafica nello Studio di Threat Hunting**:
   Nel Passo 3 della Dashboard SOC, mentre il Tab 1 ("Regole WAF") disponeva di un selettore di endpoint e di badge dedicati (`🎯 API: /api/v1/...`), il Tab 2 ("Regole SIEM") non esponeva il target endpoint nel builder né mostrava i badge nel catalogo. Inoltre, il pulsante *"🎯 Adotta Valori IP"* al Passo 2 non valorizzava l'endpoint per le regole SIEM.

## Decision

Abbiamo implementato una parità simmetrica 1:1 tra WAF e SIEM, estendendo la correlazione statistica e la risposta SOAR all'isolamento per endpoint:

### 1. Endpoint-Aware Correlation Engine (`soc/collector.py`)
- **Modello Dati Regole**: Ogni regola SIEM supporta ora il campo opzionale `endpoint` (es. `/api/v1/crypto/decrypt`, `/api/v1/auth/login`, oppure `*` / `null` per monitorare tutte le API).
- **Valutazione Dinamica**:
  Rimosso il filtro hardcoded globale `_is_decrypt_event()`. Ciascuna regola attiva valuta solo gli eventi della telemetria che soddisfano il proprio `endpoint` di riferimento.
- **Arricchimento Forense**:
  Gli incidenti generati contengono `"endpoint": target_endpoint`, fornendo al personale SOC visibilità immediata sulla route specifica bersagliata.
- **Regole Predefinite Ampliate**:
  - `rule_error_flooding`: ancorata a `/api/v1/crypto/decrypt` (con alias `/decrypt`).
  - `rule_timing_oracle`: ancorata a `/api/v1/crypto/decrypt` (latenza bimodale e side-channel crittografico).
  - `rule_byte_probing`: ancorata a `/api/v1/crypto/decrypt` (scansione sequenziale blocchi AES a 16 byte).
  - `rule_auth_bruteforce`: nuova regola predefinita mirata a `/api/v1/auth/login` (rilevamento fail-rate elevato su tentativi di autenticazione).

### 2. Scoped SOAR Active Mitigation
- La funzione `_trigger_soar_mitigation(ip, rule, reason, ttl_seconds, endpoint=...)` propaga l'endpoint target della regola direttamente all'API `/waf/block_ip` del WAF.
- Il WAF applica la quarantena sulla sola coppia `(ip, endpoint)`. Le richieste inviate dallo stesso IP verso rotte differenti continuano a essere elaborate regolarmente.

### 3. Parità Visuale e Workflow nel Threat Hunting Studio (`soc/dashboard.py`)
- **Tab 2 - Builder Regola SIEM**:
  Aggiunto il campo `🎯 Endpoint API Target (L7)` (`#new-siem-rule-endpoint`) con autocompletamento datalist (`/api/v1/crypto/decrypt`, `/api/v1/auth/login`, `*`).
- **Catalogo Regole SIEM**:
  Ogni card mostra il badge visuale `🎯 API: /api/v1/...` o `🌐 Tutte le API (*)`.
- **Eredità da Passo 2**:
  Cliccando su **"🎯 Adotta Valori IP"**, l'endpoint associato all'attore viene propagato automaticamente sia al builder WAF che al builder SIEM.
- **Backtest e Tuning**:
  Il simulatore `runHuntingBacktest()` adotta l'endpoint specificato nel tab attualmente aperto.

## Alternatives Considered

### Auto-Clustering Multidimensionale
- **Descrizione**: Calcolare deviazioni statistiche su tutte le combinazioni `(ip, endpoint)` in modo autonomo senza richiedere configurazione di endpoint nelle regole.
- **Rifiutata**: Aumenta la complessità algoritmica e riduce la trasparenza didattica nel laboratorio SOC, dove lo studente/analista deve poter comprendere e testare regole esplicite.

### Blocco Globale Host-Wide su Trigger SIEM
- **Descrizione**: Mantenere la detection per endpoint ma bloccare l'IP indistintamente su tutti i servizi.
- **Rifiutata**: Viola la decisione presa in ADR-006 sull'Availability-First Defense, causando interruzioni di servizio collaterali ingiustificate su IP condivisi.

## Consequences

- **Isolamento Completo**: Sia il perimetro preventivo (WAF) che la correlazione reattiva (SIEM) operano con granularità L7 a livello di risorsa/endpoint.
- **Flessibilità**: L'utente può creare sia regole circoscritte (es. fail-rate su `/login`) sia regole di contenimento generiche (wildcard `*`).
- **Integrazione SOAR Coerente**: L'automazione di sicurezza SOAR riflette fedelmente il modello di quarantena a tupla `(ip, endpoint)` implementato nel WAF.
