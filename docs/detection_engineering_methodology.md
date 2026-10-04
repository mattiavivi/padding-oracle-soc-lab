# Guida Metodologica: Detection Engineering Lifecycle & Strategia d'Esame

Questo documento riassume la progressione euristica, le risposte alle domande critiche d'esame e la strategia di detection/mitigazione per il lab di **Padding Oracle & SOC Engineering**.

---

## 1. Analisi e Strategia Difensiva per i Punti Critici (Discussione d'Esame)

### 1.1 Attacchi Distribuiti e Rotazione degli IP (Botnet / Residential Proxies)
* **Obiezione:** Se l'attaccante ruota decine/centinaia di IP (es. pool di proxy/botnet) effettuando meno di $\tau_{\text{probe}} = 15$ richieste per singolo IP, la regola di correlazione per `src_ip` non scatterebbe.
* **Risposta Difensiva:**
  1. **Invarianza dell'Oggetto Bersaglio (Target Ciphertext):** In un attacco Padding Oracle l'avversario cerca di decifrare uno specifico token cifrato o blocco $C_i$. Per indovinare un singolo byte occorrono in media $128$ richieste; per un blocco di 16 byte ne occorrono $\sim 2048$. Anche distribuendo su 100 nodi proxy, tutte le richieste colpiscono lo stesso endpoint condividendo il medesimo suffisso cifrato e la stessa risorsa target. Nel SOC l'aggregazione non è limitata a `by src_ip`, ma usa chiavi composite: `by (target_token_prefix, ciphertext_length)`.
  2. **Fingerprinting di Trasporto e Applicativo:** I bot o script d'attacco condividono spesso lo stesso stack TLS/HTTP (impronta JA3/JA4, ordine degli header HTTP, assenza di header tipici dei browser legittimi).
  3. **Costo Computazionale e Sequenzialità:** L'attacco di Vaudenay è rigorosamente sequenziale: indovinare il byte $k$ presuppone di aver determinato con successo il byte $k-1$. Distribuire e sincronizzare questo stato crittografico su centinaia di proxy è estremamente complesso e costoso per l'attaccante.

---

### 1.2 Latenza di Rete (WAN Jitter) vs Misurazione $t_{crypto}$
* **Obiezione:** Un differenziale artificiale di 25 ms nel Timing Oracle potrebbe venire mascherato dal network jitter (30–50 ms) su connessioni WAN geografiche.
* **Risposta Difensiva:**
  1. **Separazione Architetturale tra Telemetria Rete e APM:** Come definito in `ADR-002`, il lab registra due metriche:
     * $\Delta t_{\text{http}}$: tempo di transito end-to-end client-server (soggetto a jitter di rete).
     * $t_{\text{crypto}}$: tempo di computazione crittografica puro misurato in **nanosecondi** con clock monotonic (`time.perf_counter_ns()`) internamente al server.
  2. **Immunità del SOC al Jitter WAN:** Poiché il SOC raccoglie telemetria interna (Application Performance Monitoring / server log), **il jitter WAN esterno è pari a 0** per il motore di correlazione del SOC. Il calcolo di Sarle viene operato sul tempo CPU puro.
  3. **Asimmetria a Favore del Difensore:** Sulla WAN il jitter penalizza l'attaccante. Per distinguere un differenziale di 25 ms dal rumore di fondo, l'attaccante deve campionare ogni singolo tentativo 10–20 volte per calcolare medie statistiche. Questo decuplica il volume di richieste (da 2.000 a oltre 30.000), rendendolo esponenzialmente più rumoroso e intercettabile dal SOC.

---

### 1.3 Formalizzazione della Regola Sigma (Listing 1)
* **Obiezione:** Lo standard Sigma base descrive filtri puntuali evento-per-evento. Aggregazioni con soglie temporali, vincoli insiemistici ($|\mathcal{L}_{\text{err}}| = 1$) e modulo 16 richiedono estensioni o linguaggi di query backend.
* **Risposta Difensiva:**
  * Il Listing riportato nel paper adotta una **rappresentazione dichiarativa e astratta** (pseudocodice conforme alla logica Sigma) per esprimere la semantica SIEM in maniera indipendente dal vendor.
  * In un ecosistema enterprise, questa logica si mappa sulle **Sigma Correlation Rules (v2.0)** o viene compilata tramite `pySigma` nei linguaggi nativi dei backend:
    * **Splunk SPL:** `... | stats dc(ciphertext_len) as len_cnt, count by src_ip | where len_cnt == 1 AND count > 15 AND ciphertext_len % 16 == 0`
    * **Elastic EQL / ES|QL:** sequenze temporali con aggregazione sulla cardinalità dei campi.

---

### 1.4 Ruolo del WAF: Ispezione del Payload vs Quarantena Comportamentale
* **Domanda:** Nella realtà il WAF non vede la richiesta e l'API corretta? Perché bloccare l'IP?
* **Spiegazione Tecnica:**
  * **Il WAF Layer 7 vede tutto:** URL (`/decrypt`), header, cookie di sessione e corpo cifrato.
  * **Il Paradosso del Ciphertext:** Il WAF non possiede la chiave segreta AES dell'applicazione (che risiede esclusivamente nel backend crittografico). Una stringa cifrata manipolata da Vaudenay appare come una normale stringa Base64 pseudo-casuale, identica a un token lecito. Non esiste una "firma statica" da bloccare all'istante (come in SQLi o XSS).
  * **Quarantena Comportamentale (SOAR):** Quando il motore di detection riscontra anomalie (troppi errori di padding, probing a blocchi), il WAF applica una quarantena per IP con TTL per proteggere le risorse CPU del server. In produzione enterprise, il blocco può essere ristretto al solo endpoint `/decrypt` o alla sessione applicativa, oppure convertito in una sfida interattiva (CAPTCHA/Proof-of-Work).

---

## 2. Scala di Complessità degli Scenari di Attacco

| Livello | Nome Scenario | Parametri Attaccante / Vittima | Comportamento dell'Attaccante |
| :--- | :--- | :--- | :--- |
| **Livello 1** | **Attacco Base Volumetrico (Burst)** | `Victim: vuln`<br>`--ip-mode static`<br>`--sleep-ms 0`<br>*(no blend noise)* | **Massima velocità**, un solo IP (`198.51.100.50`), centinaia di richieste al secondo esclusivamente su `/decrypt`. |
| **Livello 2** | **Attacco Low-and-Slow (Rate Limiting Evasion)** | `Victim: vuln`<br>`--ip-mode static`<br>`--sleep-ms 200` o `500`<br>*(no blend noise)* | **Frequenza rallentata**: una richiesta ogni 200–500 ms per non superare soglie di frequenza o rate-limiting base. |
| **Livello 3** | **Attacco Furtivo con Mascheramento (Noise Blending)** | `Victim: vuln`<br>`--ip-mode static`<br>`--sleep-ms 50`<br>`--blend-noise` | **Interleaving di traffico legittimo**: alterna probe errati a chiamate lecite su `/auth/login`, `/user/profile`, `/encrypt` con esito HTTP 200, abbattendo il fail-rate sotto l'80% o il 40%. |
| **Livello 4** | **Attacco Distribuito (IP Rotation / Botnet)** | `Victim: vuln`<br>`--ip-mode rotate`<br>`--sleep-ms 50`<br>`--blend-noise` | **Rotazione IP**: ogni richiesta proviene da un IP diverso (`203.0.113.X`). Ciascun IP genera $< 15$ richieste, eludendo la soglia per-singolo-IP. |
| **Livello 5** | **Timing Side-Channel Oracle (Stealth Cryptanalitico)** | `Victim: partial`<br>`--mode timing`<br>`--sleep-ms 100` | **Error Blindness**: il server risponde con HTTP 403 generico per qualsiasi errore; l'attaccante estrae il segreto misurando il delta temporale (25 ms). |

---

## 3. L'Evoluzione Iterativa delle Regole di Rilevamento

```
[Attacco Liv. 1] ──► Regola 1 (Error Rate > 80%) ──► [Evaso da Liv. 2 & 3]
                                │
                                ▼
[Attacco Liv. 2 & 3] ──► Regola 2 (Consecutive Errors Burst) ──► [Evaso da Liv. 4 (Rotazione IP)]
                                │
                                ▼
[Attacco Liv. 4] ──► Regola 3 (Block Probing: Multiplo 16B & Lunghezza Costante) ──► [Evaso da Liv. 5 (Timing)]
                                │
                                ▼
[Attacco Liv. 5] ──► Regola 4 (Sarle Bimodality Coefficient BC > 0.555) ──► RILEVATO!
```

1. **Fase 1: Regola Naive sul Tasso di Errore**
   * *Logica:* `Fail Rate >= 80% AND Total Requests >= 15 by src_ip`.
   * *Esito:* Rileva l'attacco base ($\text{TPR} = 100\%$).
   * *Limite:* Crolla contro attacchi lenti o mascherati ($\text{TPR} = 12.5\%$) e genera falsi allarmi su client legittimi difettosi ($\text{FPR} = 6.2\%$).
2. **Fase 2: Regola sugli Errori Consecutivi**
   * *Logica:* `Consecutive Errors >= 12 by src_ip`.
   * *Esito:* Rileva l'attacco Low-and-Slow.
   * *Limite:* Aggirata dall'interleaving di richieste HTTP 200 (`--blend-noise`).
3. **Fase 3: Regola Ingegnerizzata su Invarianza Crittografica (Block Probing)**
   * *Logica:* 
     $$\text{Alert} \iff \left(|\mathcal{L}_{\text{err}}| = 1\right) \;\land\; \left(\ell_0 \equiv 0 \pmod{16}\right) \;\land\; \left(N_{\text{err}} \ge 15\right)$$
   * *Esito:* Rileva sia Low-and-Slow sia Noise Blending ($\text{TPR} = 98.8\%$, $\text{FPR} = 0.1\%$).
   * *Contro la Rotazione IP:* L'aggregazione opera su `(endpoint, ciphertext_len)` globale: centinaia di richieste errate della stessa lunghezza allineata a 16 byte attivano l'allarme distribuito.
4. **Fase 4: Regola Statistica di Bimodalità Temporale (Sarle)**
   * *Logica:* 
     $$\text{Alert}_{\text{timing}} \iff (BC \ge 0.555) \;\lor\; \left(\sigma \ge 6.0\text{ ms} \;\land\; (P_{95} - P_{50}) \ge 12.0\text{ ms}\right)$$
   * *Esito:* Rileva l'oracolo temporale nascosto sotto risposte HTTP 403 omogenee ($\text{TPR} = 95.2\%$).

---

## 4. La Soluzione Finale: Alta Fedeltà e Zero Falsi Positivi

1. **Correlazione Multivariata:** Il traffico legittimo mostra una distribuzione latenze rigorosamente unimodale ($BC \approx 0.333$), un tasso di errore basso ($2-3\%$) e lunghezze eterogenee. L'attaccante invece presenta l'invarianza del blocco e la deformazione bimodale. Il calcolo del Risk Score combinato (0–100) isola l'attacco senza intaccare gli utenti benigni.
2. **Mitigazione SOAR Adattiva:** Introduzione di Tarpit/Throttling esponenziale anziché blocco cieco dell'IP: un ritardo di 500 ms è impercettibile per un utente sporadico, ma rende l'attacco crittografico (che richiede migliaia di query) impraticabile.
3. **Chiusura Crittografica Definitiva (*Encrypt-then-MAC*):** Passaggio a `victim-fixed` (HMAC-SHA256 verificato in tempo costante prima della decifratura). L'oracolo cessa di esistere matematicamente.

---

## 5. Architettura WAF Layer 7 Universale Zero-Touch & Scoping SIEM (ADR-006)

Per garantire la scalabilità difensiva in ambienti microservizi enterprise (`/api/v1/crypto/decrypt`, `/api/v1/auth/login`, ecc.), l'architettura adotta due pilastri chiave (cfr. [ADR-006](decisions/ADR-006-universal-l7-zero-touch-waf-and-scoped-hunting.md)):

### 5.1 Motore WAF Zero-Touch e Isolamento per Endpoint
* **Ispezione Inbound Universale (`@app.before_request`):** Tutte le richieste in ingresso vengono intercettate prima dei controller applicativi. I controller rimangono pure funzioni di business logic ("zero-touch").
* **Registrazione Outbound (`@app.after_request`):** Lo status HTTP (anomalia se $\ge 400$, successo se $< 400$) alimenta la sliding window dell'IP limitatamente all'endpoint invocato.
* **Isolamento Rigoroso `(ip, endpoint)`:** Un ban per brute-force su `/api/v1/auth/login` isola l'IP esclusivamente su tale API. Le richieste legittime dello stesso IP verso `/api/v1/crypto/decrypt` o `/health` continuano a funzionare regolarmente (e viceversa), eliminando il rischio di DoS collaterale su gateway NAT o client multi-tasking.

### 5.2 Workflow Reattivo a Cascata nel Threat Hunting Studio
* **Passo 1 (Scope Provider):** L'analista formula query SIEM mirate (es. `endpoint = /api/v1/auth/login` o `src_ip = ...`).
* **Passo 2 (Scope Consumer):** L'endpoint `/hunting/explore?query=...` calcola i profili attori (richieste, fail-rate, bimodalità) **esclusivamente** sugli eventi che soddisfano il filtro di Passo 1, esponendo il banner visivo `🔎 Scope Attivo da Passo 1`.
* **Passo 3 (Ingegneria Regole & Catalogo WAF):** Il comando **"🎯 Adotta Valori IP"** eredita sia le metriche sia l'endpoint target dell'attore profilato. Il catalogo visualizza badge espliciti per ciascuna regola (`🎯 API: /api/v1/crypto/decrypt`, `🎯 API: /api/v1/auth/login`, `🌐 Tutte le API (*)`).

---

## 6. Procedura di Esecuzione dei Test Live

1. **Avvio dei servizi core:**
   ```bash
   ./start.sh up
   ```
2. **Generazione del traffico legittimo di fondo (10 client concorrenti):**
   ```bash
   ./start.sh start-benign
   ```
3. **Esecuzione dell'attacco:**
   * *Attacco Base:* `./start.sh run-attack`
   * *Attacco Mascherato Low-and-Slow:*
     ```bash
     docker compose exec attacker python attack.py --sleep-ms 100 --blend-noise
     ```
   * *Attacco Timing Oracle:* (dopo aver commutato su `victim-partial` via UI o API)
     ```bash
     docker compose exec attacker python attack.py --mode timing --sleep-ms 50
     ```
4. **Verifica via Dashboard:** Monitorare gli eventi, il Risk Score e l'attivazione della quarantena WAF in tempo reale su `http://localhost:18091`.
