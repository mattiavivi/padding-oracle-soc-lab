# Task List: WAF Layer 7 Universale Zero-Touch e Cascata Threat Hunting SIEM

- [x] Task 1: Motore WAF Universale Zero-Touch in `victim/app.py`
  - Acceptance: Implementazione dei middleware hook `@app.before_request` e `@app.after_request`. Le rotte applicative non contengono chiamate WAF esplicite. `WAF_STATE` memorizza tuple `(timestamp, is_error, endpoint)`. `_check_waf_block` valuta ciascuna regola filtrando gli eventi pertinenti all'endpoint della regola. Le route di gestione (`/health`, `/waf/*`, `/mode`) sono esenti. Se `WAF_POLICY["enabled"] == False`, nessun blocco viene emesso.
  - Verify: Esecuzione `PYTHONPATH=. /home/sysadmin/.local/bin/uv run pytest tests/test_victim_waf.py` con esito positivo.
  - Files: `victim/app.py`, `control/waf_policy.json`

- [x] Task 2: Backend Query-Aware e Scoping Endpoint in `soc/collector.py`
  - Acceptance: In `soc/collector.py`, `/hunting/explore` accetta il parametro `query`. Se presente e diverso da `*`, gli eventi difensivi della vittima vengono filtrati con `filter_events(events, query)` prima di raggruppare per IP e calcolare le feature statistiche. In `/hunting/backtest`, la regola viene testata sul subset di eventi corrispondente al suo endpoint. `_generate_sigma_rule` riceve ed espone l'endpoint corretto.
  - Verify: Chiamata di test a `/hunting/explore?query=endpoint%20%3D%20%2Fapi%2Fv1%2Fauth%2Flogin` verifica che `ip_profiles` contenga solo metriche relative a `/api/v1/auth/login`.
  - Files: `soc/collector.py`

- [x] Task 3: Integrazione Frontend Cascata Passo 1 -> Passo 2 in `soc/dashboard.py`
  - Acceptance: `executeSiemQuery()` invoca `loadHuntingData(currentSiemQuery)` per aggiornare istantaneamente la telemetria grezza. `/hunting/data` inoltra la query al backend o al fallback locale. `renderHuntingProfilesTable()` visualizza il banner dello Scope Attivo (`🔎 Scope Attivo da Passo 1: [...]`) e adatta dinamicamente le colonne in base al contesto (login, decrypt o totale). `applyActorAsThresholds()` eredita l'endpoint dallo Scope attivo.
  - Verify: Verifica manuale del rendering JS e assenza di errori nella console browser.
  - Files: `soc/dashboard.py`

- [x] Task 4: UI Passo 3: Scoping WAF e Badge nel Catalogo in `soc/dashboard.py`
  - Acceptance: Aggiunta del campo `Endpoint API Target` nel builder regole WAF (`#new-waf-rule-endpoint`) con pre-selezione automatica. In `addNewWafRule()`, il campo `endpoint` viene inviato a `/waf/rules/add`. In `loadWafRulesStatus()`, ogni regola nel catalogo mostra un badge evidente con l'endpoint presidiato (`🎯 API: /api/v1/crypto/decrypt`, `🎯 API: /api/v1/auth/login`, ecc.).
  - Verify: Verifica del payload inviato a `/waf/rules/add` e rendering corretto dei badge nel catalogo.
  - Files: `soc/dashboard.py`

- [x] Task 5: Suite di Test Unitari e di Integrazione L7
  - Acceptance: Creazione di `tests/test_l7_universal_waf.py` per validare:
    1. Blocco 429 automatico su `/api/v1/auth/login` dopo 5 errori consecutivi via `@app.before_request` / `@app.after_request`.
    2. Isolamento perfetto: superamento soglia su `/login` non influenza `/decrypt` per lo stesso IP.
    3. Trasparenza quando il WAF è disattivato (`enabled: false`).
    4. Cascata SIEM: `/hunting/explore?query=...` restituisce dati filtrati per IP ed endpoint.
  - Verify: Esecuzione `PYTHONPATH=. /home/sysadmin/.local/bin/uv run pytest tests/test_l7_universal_waf.py tests/test_victim_waf.py tests/test_ip_rotation_per_query.py` con 100% passed.
  - Files: `tests/test_l7_universal_waf.py`
