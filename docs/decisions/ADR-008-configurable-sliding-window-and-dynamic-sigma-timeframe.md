# ADR-008: Configurable Sliding-Window Timeframes in Layer 7 WAF and Dynamic Sigma Rule Compilation

## Status
Accepted

## Date
2026-10-04

## Context
Nelle architetture difensive crittografiche introdotte in [ADR-003](ADR-003-closed-loop-soar-active-waf-mitigation.md) e [ADR-006](ADR-006-universal-l7-zero-touch-waf-and-scoped-hunting.md), il Web Application Firewall (WAF) inline di [`victim/app.py`](../../victim/app.py) protegge gli endpoint dell'applicazione tramite un algoritmo a *sliding-window* in-memory:
- Le richieste e gli errori crittografici (es. `padding_error`, HTTP 500, HTTP 401) vengono registrati in un buffer sequenziale per ciascun IP sorgente.
- Se il volume totale di richieste in finestra supera una soglia minima (`min_requests_window`) e il tasso di fallimento crittografico (`fail_rate`) o gli errori consecutivi (`consecutive_errors`) eccedono i limiti, l'IP viene isolato e inserito in quarantena temporanea (`ban_ttl_seconds`).

Tuttavia, prima di questa decisione, la finestra di osservazione temporale presentava una rigidità strutturale:
1. **Hardcoding a 60 secondi nella UI e nel generatore Sigma**:
   Il form di creazione delle regole WAF nella Dashboard SOC non esponeva il parametro della finestra temporale, costringendo `addNewWafRule()` a salvare sempre `window_seconds: 60`. Inoltre, il template di generazione delle regole Sigma YAML in [`soc/collector.py`](../../soc/collector.py) e [`soc/dashboard.py`](../../soc/dashboard.py) compilava rigidamente la direttiva `timeframe: 60s`.
2. **Vettore di Evasione "Low-and-Slow" (Dilatazione Temporale)**:
   In un attacco Padding Oracle, l'attaccante deve inviare centinaia di probe crittografici per decifrare un token AES-CBC blocco per blocco. Se l'attaccante introduce un ritardo intenzionale (es. 5-10 secondi tra una sonda e l'altra con `--min-sleep-ms 5000`), nell'arco di qualsiasi finestra di 60s transitano al massimo 6-12 richieste. Poiché la soglia di burst minima è tipicamente `>= 15`, la finestra mobile fa decadere gli eventi precedenti prima che la condizione di blocco venga soddisfatta. L'attaccante riesce quindi a portare a termine la decifrazione completa senza mai essere intercettato dal WAF.

## Decision

Abbiamo reso la finestra temporale (`window_seconds`) completamente configurabile per singola regola, sincronizzandola tra interfaccia grafica, motore di enforcement WAF e generatore di regole Sigma:

### 1. Interfaccia Grafica e Calibrazione Parametri (`soc/dashboard.py`)
- **Nuovo Campo di Input WAF Builder**: Aggiunto il controllo `#hunt-waf-window` con label *"Finestra Temporale (s)"* (*Sliding Window*), configurabile tra 5 e 3600 secondi (step 5s, default 60s).
- **Adeguamento Label Semantiche**: Aggiornata la dicitura *"Min Richieste / 60s"* in *"Min Richieste / Finestra"* sia nel tab WAF che nel tab SIEM.
- **Binding Dinamico**: La funzione JavaScript `addNewWafRule()` acquisisce il valore impostato e lo serializza nel payload della regola. La funzione `runHuntingBacktest()` trasmette `window_seconds` all'endpoint di simulazione forense.

### 2. Generazione Dinamica di Specifiche Sigma YAML (`soc/collector.py` & `soc/dashboard.py`)
- La funzione `_generate_sigma_rule(rules)` estrae dinamicamente il parametro `timeframe_sec = max(5, int(rules.get("window_seconds", rules.get("timeframe", 60))))`.
- Il template Sigma esportato compila fedelmente:
  ```yaml
  detection:
    selection_endpoint:
      endpoint:
        - '{endpoint}'
    selection_status:
      status_code:
        - {status_filter}
    timeframe: {timeframe_sec}s
    condition_error_rate:
      selection_endpoint and selection_status and count() >= {min_events} by src_ip
      and failure_rate >= {fail_rate}
  ```
- Ciò consente agli analisti SOC di esportare regole di rilevamento calibrate (es. `timeframe: 300s` o `timeframe: 600s`) direttamente spendibili in SIEM di produzione (Splunk, Elastic, Sentinel).

### 3. Validazione e Enforcement Multi-Finestra nel WAF L7 (`victim/app.py`)
- **API Endpoints**: Gli endpoint `/waf/rules/add` e `/waf/rules/update` convalidano e normalizzano `window_seconds` come intero compreso tra 5 e 86400 secondi.
- **Gestione Buffer Eterogenei**: Poiché regole diverse possono avere finestre differenti (es. regola anti-burst su 30s e regola anti-slow attack su 300s), `_check_waf_block()` determina la finestra massima attiva (`max_window = max(rule.window_seconds)`), preserva in `WAF_STATE[ip]` solo gli eventi necessari e valuta ciascuna regola esclusivamente sul proprio sottoinsieme temporale (`now - ts <= window_sec`).

## Alternatives Considered

### 1. Finestre Temporali Fisse a Tendina (Preset 1m, 5m, 15m)
- **Motivo del rifiuto**: Limita la flessibilità dell'analista durante le attività di Threat Hunting e calibrazione fine delle soglie su attacchi a diversa cadenza di campionamento.

### 2. Algoritmo Token Bucket o Leaky Bucket
- **Motivo del rifiuto**: Il token bucket tradizionale non memorizza l'esito puntuale dei singoli eventi (status code, endpoint specifico, tipo di errore crittografico). Non permetterebbe di distinguere tra sequenze consecutive di soli errori crittografici (`consecutive_errors`) e traffico lecito intercalato.

### 3. Correlazione Esclusiva nel SIEM Out-of-Band
- **Motivo del rifiuto**: Il rilevamento post-mortem nel SIEM (tramite query di aggregazione a 5 o 15 minuti) non fornisce protezione preventiva in tempo reale, consentendo all'attaccante di completare l'estrazione della chiave o del plaintext prima dell'intervento manuale.

## Consequences

- **Positivi**:
  - Mitigazione efficace degli attacchi Padding Oracle condotti a bassa frequenza (Low-and-Slow evasion).
  - Piena coerenza e parità tra la regola visualizzata in UI, applicata dal WAF ed esportata in formato standard Sigma.
  - Possibilità di definire regole WAF a finestra stretta (es. burst 30s) in contemporanea con regole a finestra estesa (es. slow scan 600s) sullo stesso endpoint.
- **Trade-off / Monitoraggio**:
  - Finestre temporali molto ampie (es. > 3600s) con volumi di traffico elevati aumentano la memoria occupata da `WAF_STATE` per ciascun IP. La retention viene comunque troncata rigorosamente a `max_window` ad ogni nuova richiesta.
