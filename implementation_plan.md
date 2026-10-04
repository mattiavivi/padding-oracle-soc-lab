# Spec & Implementation Plan: WAF Layer 7 Universale Zero-Touch e Cascata Threat Hunting SIEM

> **Riferimento:** ADR-005 e Analisi Architetturale WAF Layer 7  
> **Data:** 2026-09-26  
> **Stato:** In attesa di approvazione (STOP Phase)

---

## ASSUNZIONI DI PARTENZA
1. **WAF Trasparente Zero-Touch:** Nessun controller applicativo in `victim/app.py` (`decrypt`, `auth_login`, `user_profile` o endpoint futuri) deve contenere chiamate WAF cablate a mano. L'ispezione preventiva e la registrazione esiti avvengono interamente a livello di framework tramite middleware hooks Flask (`@app.before_request` e `@app.after_request`).
2. **Isolamento Rigoroso per Endpoint:** Lo stato della sliding-window e la quarantena dell'IP isolano le metriche per endpoint: violare le soglie su `/api/v1/auth/login` genera un ban perimetrale limitato a quell'API, preservando la disponibilità di `/api/v1/crypto/decrypt` e degli altri servizi per lo stesso IP (e viceversa).
3. **Flusso a Cascata SIEM Explorer (Passo 1 $\to$ Passo 2 $\to$ Passo 3):** La query SIEM formulata al Passo 1 definisce lo Scope analitico del Passo 2. La profilazione attori aggrega esclusivamente il sottoinsieme di eventi risultanti da tale query. Il Passo 3 eredita l'endpoint dallo Scope e consente la creazione/visualizzazione di regole WAF e Sigma associate all'API target.
4. **Isolamento Telemetria Server (ADR-005):** Tutti i calcoli difensivi e le aggregazioni SIEM continuano a operare con autorevolezza unicamente sugli eventi generati dalla vittima (`service == "victim"`).

---

## 1. SPECIFICA TECNICA

### 1.1 Obiettivo
Rendere l'architettura difensiva del laboratorio un vero WAF enterprise di Layer 7 trasparente ed estendere l'interfaccia di Threat Hunting & SIEM Explorer con un workflow integrato a 3 passi:
1. **Motore WAF Universale in `victim/app.py`:**
   - Intercettazione inbound automatica su tutte le richieste HTTP applicative quando `WAF_POLICY["enabled"] == True`.
   - Registrazione outbound automatica degli esiti (errori $\ge 400$ vs successi $< 400$) indicizzati per endpoint.
   - Rimozione del codice WAF legacy cablato all'interno di `decrypt()`.
   - Esclusione trasparente delle route interne di controllo (`/health`, `/waf/*`, `/mode`, `/metrics`, `/static/*`).
2. **Cascata Passo 1 $\to$ Passo 2 nel SIEM:**
   - Estensione di `/hunting/explore` e del fallback dashboard per accettare la `query` SIEM ed eseguire la profilazione attori sul sottoinsieme di eventi filtrati.
   - Aggiunta nella UI del banner di *Scope Attivo* e adattamento dinamico delle colonne della tabella (metriche di login se la query è su `/login`, metriche crittografiche se su `/decrypt`, metriche globali con breakdown se `*`).
3. **Ingegneria Regole WAF al Passo 3:**
   - Campo *Endpoint API Target* nel form di creazione WAF, pre-popolato dall'endpoint attivo dello Scope.
   - Visualizzazione chiara dell'endpoint tramite badge colorati nel catalogo delle regole WAF (`🎯 API: /api/v1/crypto/decrypt`, `🎯 API: /api/v1/auth/login`, `🌐 Tutte le API`).
   - Sincronizzazione della preview Sigma YAML con l'endpoint selezionato.
4. **Policy Predefinite Multi-API in `control/waf_policy.json`:**
   - Introduzione di regole native per la protezione di `/api/v1/crypto/decrypt` (Padding Oracle & Consecutive Probing) e di `/api/v1/auth/login` (Credential Spraying & Brute-Force).

### 1.2 Tech Stack
- **Framework & Server:** Python 3.12+, Flask 3.x, Werkzeug, SQLite 3 (WAL mode).
- **WAF Engine:** In-memory sliding-window L7 con tuple `(timestamp, is_error, endpoint)`, TTL-aware block table (`WafBlockList`).
- **Frontend:** Vanilla JavaScript (ES6+), HTML5, CSS custom variables, Lucene-like SIEM Query Parser.
- **Testing:** `pytest`, Flask Test Client, `uv run pytest`.

### 1.3 Comandi Eseguibili
```bash
# Esecuzione test suite WAF e regressione
PYTHONPATH=. /home/sysadmin/.local/bin/uv run pytest tests/test_victim_waf.py tests/test_ip_rotation_per_query.py -v

# Esecuzione test specifici per il nuovo WAF universale L7 e la cascata SIEM
PYTHONPATH=. /home/sysadmin/.local/bin/uv run pytest tests/test_l7_universal_waf.py -v

# Smoke test completo
./tests/smoke.sh
```

### 1.4 Struttura del Progetto Coinvolta
```
victim/
  └── app.py                       # Hook universali @app.before_request e @app.after_request, WAF_STATE isolato
soc/
  ├── collector.py                 # /hunting/explore e /hunting/backtest con supporto query SIEM e endpoint filter
  └── dashboard.py                 # Cascata JS Passo 1 -> Passo 2, form Passo 3 con Endpoint, catalogo badge L7
control/
  └── waf_policy.json              # Catalogo policy con regole esplicite per /decrypt e /auth/login
tests/
  ├── test_victim_waf.py           # Aggiornamento test esistenti per conformità al middleware
  └── test_l7_universal_waf.py     # Nuovi test unitari per middleware trasparente, isolamento route e cascata SIEM
```

### 1.5 Code Style & Convenzioni
- Hook Flask puliti e non intrusivi:
  ```python
  @app.before_request
  def waf_inbound_filter():
      if not WAF_POLICY.get("enabled"):
          return None
      if request.path in EXEMPT_PATHS or request.path.startswith("/waf/"):
          return None
      ip = _client_ip()
      is_blocked, reason = _check_waf_block(ip, endpoint=request.path)
      if is_blocked:
          _log_request(request.path, 429, 0.5, 0, "waf_blocked", extra_details={"waf_reason": reason})
          return jsonify({"error": "WAF_PREVENTIVE_BLOCK", "message": reason, "endpoint": request.path, "ip": ip}), 429
      return None
  ```
- Tuple di stato a 3 elementi: `(timestamp: float, is_error: bool, endpoint: str)`.
- Matching flessibile per endpoint: `rule_ep == "*" or rule_ep in req_ep or req_ep in rule_ep`.

### 1.6 Testing Strategy
1. **Unit Test WAF Middleware Zero-Touch:**
   - Invio di 5 tentativi di login errati (`POST /api/v1/auth/login` con password errata). Verifica trigger HTTP 429 al 6° tentativo senza che `auth_login()` contenga codice WAF.
   - Invio di richieste a `/api/v1/crypto/decrypt` dallo stesso IP: verifica risposta HTTP regolare (nessun blocco incrociato).
2. **Unit Test Toggle WAF Globale:**
   - Con `WAF_POLICY["enabled"] == False`, verificare che raffiche di errori non provochino mai HTTP 429.
3. **Integration Test Cascata SIEM:**
   - Invocare `/hunting/explore?query=endpoint%20%3D%20%2Fapi%2Fv1%2Fauth%2Flogin`: verificare che `ip_profiles` restituisca solo attori ed eventi pertinenti a `/api/v1/auth/login`.
   - Invocare `/hunting/explore?query=*`: verificare il calcolo globale su tutti gli endpoint.

### 1.7 Limiti e Confini (Boundaries)
- **Sempre fare:** preservare l'esenzione WAF per gli endpoint diagnostici e di gestione (`/health`, `/waf/*`, `/mode`). Preservare la compatibilità di `_check_waf_block(ip, endpoint)`.
- **Chiedere prima:** introduzione di dipendenze esterne aggiuntive.
- **Mai fare:** inserire controlli `if is_blocked` all'interno delle funzioni di rotta applicativa. Non alterare la logica crittografica di decifratura CBC e padding check.

### 1.8 Criteri di Successo
1. Qualsiasi richiesta HTTP verso qualsiasi rotta applicativa esistente o futura passa attraverso l'ispezione preventiva del WAF quando abilitato.
2. Un attacco di brute force su `/api/v1/auth/login` viene bloccato dal WAF con HTTP 429 senza influenzare `/api/v1/crypto/decrypt` per lo stesso IP.
3. Eseguendo una query al Passo 1 (es. su un endpoint o su IP specifici), la telemetria del Passo 2 riflette istantaneamente e unicamente i dati di quella query.
4. Al Passo 3, il catalogo WAF mostra visivamente l'endpoint associato a ciascuna regola e consente di creare nuove regole con endpoint specificabile.
5. Tutti i test della suite (`uv run pytest`) passano con esito 100% verde.

---

## 2. PIANO DI IMPLEMENTAZIONE TECNICA

### Fase 1: Motore WAF Universale in `victim/app.py`
1. Aggiornare `WAF_STATE` per memorizzare tuple a 3 elementi `(timestamp, is_error, endpoint)`.
2. Aggiornare `_check_waf_block(ip, endpoint)` affinché la sliding window estragga solo gli eventi compatibili con `rule_endpoint`.
3. Aggiungere `@app.before_request` per l'ispezione preventiva centralizzata di tutte le rotte applicative.
4. Aggiungere `@app.after_request` per la registrazione outbound centralizzata di successi ed errori basati su `response.status_code >= 400`.
5. Rimuovere da `decrypt()` le vecchie chiamate manuali a `_check_waf_block()` e `_record_waf_outcome()`.
6. Aggiornare `control/waf_policy.json` con regole esplicite per `/api/v1/crypto/decrypt` e `/api/v1/auth/login`.

### Fase 2: Backend Query-Aware in `soc/collector.py` e `soc/dashboard.py`
1. Modificare `hunting_explore()` in `soc/collector.py` per accettare il parametro `query`. Se valorizzato e diverso da `*`, filtrare gli eventi difensivi della vittima tramite `filter_events(events, query)` prima di calcolare i profili IP.
2. Allineare il fallback locale di `hunting_data()` in `soc/dashboard.py` con il medesimo supporto per `query`.
3. Aggiornare `hunting_backtest()` per verificare la regola candidata solo sugli eventi storici che matchano l'endpoint della regola.

### Fase 3: Interfaccia Grafica a Cascata in `soc/dashboard.py`
1. Modificare `executeSiemQuery()`: all'esecuzione della query, invocare `loadHuntingData(currentSiemQuery)`.
2. Modificare `loadHuntingData(query)`: trasmettere la query attiva a `/hunting/data`.
3. In `renderHuntingProfilesTable()`: inserire il banner dello Scope Attivo del Passo 1 e adattare le etichette delle colonne in base all'endpoint attivo.
4. Modificare `applyActorAsThresholds()`: pre-popolare il campo endpoint del Passo 3 con l'endpoint attivo nello Scope.
5. Nel form WAF del Passo 3: aggiungere il campo input/select `#new-waf-rule-endpoint`.
6. In `addNewWafRule()`: inviare il campo `endpoint` al backend.
7. In `loadWafRulesStatus()`: renderizzare il badge `🎯 API: <endpoint>` nella card di ogni regola WAF.

### Fase 4: Test Suite e Verifica Funzionale
1. Creare `tests/test_l7_universal_waf.py` con test completi per:
   - WAF middleware trasparente su `/login` e `/decrypt`.
   - Isolamento cross-endpoint dello stato di blocco.
   - Cascata di query SIEM su `/hunting/explore`.
2. Eseguire l'intera suite di test con `uv run pytest`.
