# ADR-006: Universal Layer 7 Zero-Touch WAF and Scoped Threat Hunting Cascade

## Status
Accepted

## Date
2026-09-26

## Context
Nel passaggio da un oracolo monolitico a una vera architettura microservizi REST crittografica aziendale (`/api/v1/crypto/decrypt`, `/api/v1/auth/login`, `/api/v1/crypto/encrypt`, `/api/v1/user/profile`, ecc.), sono emerse tre limitazioni architetturali:

1. **Accoppiamento Codice-Sicurezza nelle Route**:
   Il codice di controllo WAF e la registrazione degli esiti erano precedentemente invocati a mano all'interno dell'handler di `/decrypt`. L'introduzione di nuovi endpoint applicativi avrebbe richiesto la duplicazione manuale dei controlli di sicurezza in ciascuna funzione di route, violando i principi di modularità e manutenibilità.
2. **Mancanza di Isolamento per Endpoint (Rischio DoS Collaterale)**:
   In un'infrastruttura con IP condivisi (es. NAT gateway aziendali o workstation multi-servizio), un blocco indiscriminato dell'IP a livello host blocca tutte le comunicazioni. Un attacco di credential stuffing su `/api/v1/auth/login` avrebbe provocato l'inaccessibilità anche dei servizi crittografici legittimi (`/decrypt`) per quel medesimo IP, e viceversa.
3. **Disconnessione nel Workflow del Threat Hunting Studio**:
   Nello Studio di Threat Hunting della Dashboard SOC (`soc/dashboard.py`), il **Passo 1** (Esplorazione Log SIEM & Filtro Query) era scollegato dal **Passo 2** (Telemetria Grezza: Profilazione Attori & Feature Crittografiche). Eseguire una query specifica (es. per IP o per endpoint di autenticazione) non riduceva lo scope del calcolo delle metriche statistiche (richieste, fail-rate, bimodalità), che continuavano a essere calcolate sul traffico globale o unicamente su `/decrypt`. Inoltre, il catalogo WAF al **Passo 3** non rendeva esplicito quale endpoint fosse protetto da ciascuna regola.

## Decision

Abbiamo implementato un'architettura **Universal Layer 7 Zero-Touch WAF** unita a una pipeline reattiva di **Threat Hunting Cascading**:

### 1. Motore WAF Universale Zero-Touch (`victim/app.py`)
- **Ispezione Inbound Automatica (`@app.before_request`)**:
  Intercetta in ingresso ogni richiesta HTTP verso qualsiasi rotta prima dell'esecuzione del controller. Se il WAF è attivo (`WAF_POLICY["enabled"] == true`), confronta le regole attive per l'endpoint target. Se l'IP o la tupla `(ip, endpoint)` è in quarantena o sfora la sliding-window di errori, restituisce immediatamente `HTTP 429 Too Many Requests` (`WAF_PREVENTIVE_BLOCK`), senza eseguire il controller applicativo.
- **Registrazione Outbound Trasparente (`@app.after_request`)**:
  Analizza l'esito reale generato da qualsiasi handler: le risposte con status $\ge 400$ vengono archiviate come fallimenti/anomalie, mentre quelle $< 400$ come successi nella sliding-window dell'endpoint.
- **Pulizia Completa delle Rotte**:
  Rimosso ogni frammento di codice WAF manuale dalle funzioni di business logic (`decrypt`, `auth_login`, ecc.), rendendole pure e conformi al pattern Zero-Touch.
- **Eccezioni Applicative Esenti**:
  Rotte operative e diagnostiche (`/health`, `/mode`, `/waf/*`, `/metrics`) sono formalmente esentate dai filtri per garantire l'ininterrotta operatività dei controlli infrastrutturali.

### 2. Isolamento Rigoroso per Endpoint
- `WAF_STATE` memorizza tuple a 3 elementi `(timestamp, is_error, endpoint)`.
- `WafBlockList` indicizza i blocchi temporizzati tramite chiavi `(ip, endpoint)`.
- **Comportamento isolato garantito**: Se un aggressore effettua brute force su `/api/v1/auth/login` e viene bloccato (HTTP 429 su `/login`), le richieste inviate dallo stesso IP verso `/api/v1/crypto/decrypt` o `/health` continuano a essere elaborate normalmente.

### 3. Workflow a Cascata nel Threat Hunting Studio (`soc/collector.py` & `soc/dashboard.py`)
- **Passo 1 (Scope Provider)**:
  L'esecuzione di una query SIEM (es. `endpoint = /api/v1/auth/login`) attiva reattivamente `loadHuntingData(currentSiemQuery)`.
- **Passo 2 (Scope Consumer & Profiler)**:
  L'endpoint `/hunting/explore?query=...` filtra la telemetria difensiva tramite `evaluate_event_query` prima di aggregare per IP. La tabella della telemetria grezza calcola volumi, tassi di fallimento e bimodalità limitatamente al sottoinsieme di eventi che soddisfano la query, esponendo il banner visivo `🔎 Scope Attivo da Passo 1`.
- **Passo 3 (Tuning Regole & Badge Catalogo)**:
  - Il form di calibrazione include il campo `🎯 Endpoint API Target (L7)` (`#new-waf-rule-endpoint`).
  - Cliccando su **"🎯 Adotta Valori IP"** al Passo 2, il target endpoint dell'attore profilato viene ereditato automaticamente nel builder del Passo 3.
  - Il Live Backtest WAF valuta la soglia candidata isolandola sull'endpoint indicato e genera la specifica Sigma YAML corrispondente.
  - Nel Catalogo delle Regole WAF, ogni card mostra un badge distintivo (`🎯 API: /api/v1/crypto/decrypt`, `🎯 API: /api/v1/auth/login`, `🌐 Tutte le API (*)`).

## Alternatives Considered

### Decoratore Manuale per Rotta (`@waf_protected(endpoint=...)`)
- **Pro**: Esplicita visibilità del decoratore nel codice Python della route.
- **Contro**: Rischio di dimenticare il decoratore su nuovi endpoint; viola il principio Zero-Touch; sporca il codice delle rotte applicative.
- **Rifiutata**: I middleware hook standard `@app.before_request` e `@app.after_request` garantiscono una protezione perimetrale universale e non invasiva.

### Blocco Globale IP a Livello Host (Ban su tutti gli endpoint)
- **Pro**: Semplicità di implementazione (chiave singola `ip`).
- **Contro**: Causa denial-of-service accidentale su servizi critici leciti per IP che condividono lo stesso gateway NAT o per client aziendali multi-tasking.
- **Rifiutata**: In un WAF L7 moderno, l'isolamento della risorsa/endpoint garantisce il principio di minima interruzione del servizio (*availability-first defense*).

## Consequences

- **Modularità Estrema**: Aggiungere un nuovo endpoint applicativo (es. `/api/v1/token/revoke`) in futuro richiede zero modifiche al sistema di sicurezza: eredita automaticamente ispezione, conteggio errori e isolamento WAF.
- **Accuratezza Forense & Hunting**: L'analista SOC può focalizzare l'analisi su un singolo vettore d'attacco (spray password vs padding oracle) senza che i calcoli statistici vengano inquinati dal traffico di altri endpoint.
- **Testabilità e Robustezza**: Convalidato da una suite dedicata di test unitari e di integrazione (`tests/test_l7_universal_waf.py`), con esito 100% passed (45/45 test di laboratorio conformi).
