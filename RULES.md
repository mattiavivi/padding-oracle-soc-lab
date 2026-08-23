# Padding Oracle SOC Lab — Rules File (AI Context)

## Obiettivo del Progetto

Progetto universitario che dimostra il **Padding Oracle Attack su AES-CBC** in un ambiente containerizzato.
Due livelli:
1. **Crypto Core** — attacco reale (attacker → victim)
2. **SOC Layer** — raccolta log, metriche real-time, dashboard per osservare l'attacco

Il destinatario finale è un docente universitario / pubblico SOC: deve **capire visivamente** cosa sta succedendo, chi è l'attaccante, chi è benigno, e se l'attacco ha successo.

---

## Stack Tecnico

| Layer | Tecnologia |
|---|---|
| Backend servizi | Python 3.12, Flask |
| Containerizzazione | Docker + docker-compose |
| UI (SOC Dashboard) | Flask + HTML/CSS/JS inline (render_template_string) |
| Log | JSONL files in runtime-logs/ |
| Network visualization | vis-network.min.js (in soc/static/) |
| Comunicazione SOC | REST HTTP (soc collector espone /alerts /metrics) |

## Comandi Chiave

```bash
cd /home/sysadmin/test/project/padding-oracle-soc-lab
docker compose up -d --build soc-ui
./control/scenario.sh up-vuln
./control/scenario.sh start-benign
./control/scenario.sh run-attack
curl -s http://localhost:18090/alerts
```

## Architettura Container

```
docker network: padding-oracle-soc-lab_default

Sempre attivi:
  soc        (port 18090) — collector: /health /metrics /alerts
  soc-ui     (port 18091) — dashboard Flask

Vittime (una sola attiva per volta):
  victim-vuln    (port 18080) — AES-CBC raw, distingue padding_error
  victim-partial (port 18081) — timing side-channel, risposta generica
  victim-fixed   (port 18082) — timing costante, risposta generica

Client (gestiti dalla UI):
  benign-1, benign-2  — traffico normale (--iterations --min-sleep-ms --max-sleep-ms)
  attacker            — padding oracle attack (--mode vuln|timing --sleep-ms)
```

## Log Format (JSONL)

Ogni servizio scrive in runtime-logs/<service>.jsonl:
```json
{
  "ts": "2026-07-27T20:00:00+00:00",
  "service": "victim|attacker|benign-1|benign-2",
  "event_type": "http_request|benign_request|attack_progress|attack_complete",
  "scenario_id": "vuln|partial|fixed|baseline|attack-vuln",
  "src_ip": "attacker|benign-1|...",
  "endpoint": "/decrypt|/encrypt",
  "status_code": 200,
  "latency_ms": 12.345,
  "ciphertext_len": 48,
  "error_type": "ok|padding_error|integrity_error|generic_error",
  "details": {}
}
```

Come distinguere attaccante da benigni:
- service == "attacker" o event_type == "attack_progress|attack_complete" → HACKER (rosso)
- service == "benign-1" o "benign-2" → BENIGNO (giallo)
- service == "victim" → log del server vittima (grigio)

## Convenzioni Codice

- Python 3.12 con type hints ovunque
- emit_event(service_name, event_dict) in common/event_logger.py
- UI completamente in soc/dashboard.py (Jinja2 inline)
- NON aggiungere dipendenze senza verificare il Dockerfile
- Aggiornare RULES.md se cambia architettura o pattern

## Confini

- NON modificare common/crypto_utils.py
- NON modificare victim/app.py senza delibera
- NON aggiungere servizi a docker-compose senza accordo
- runtime-logs/ è effimero

---

## Stato Attuale UI — Problemi

1. Nessuna dashboard con rete centrale e interattiva
2. Non si capisce se l'attacco è attivo
3. Click su host non fa nulla (rete è pagina separata non interattiva)
4. Log non in tempo reale (serve F5 manuale)
5. Client benigni: numero richieste non configurabile dalla UI
6. Attaccante: parametri non modificabili dalla UI
7. Log non colorati per tipo (attaccante vs benigno non distinguibili)
8. Menu nav minimale, nessun stato

---

## Piano UI Target

### Layout Principale (pagina unica /)
SIDEBAR (sinistra) + MAIN (destra):
- Sezione Network: topologia vis-network interattiva
  - Click victim: modale switch vuln/partial/fixed
  - Click benign: modale N-richieste + sleep-ms
  - Click attacker: modale mode + sleep-ms
- Sezione Log: stream real-time colorato (poll ogni 2s)
  - Rosso = attacker, Giallo = benign, Grigio = victim
- Header: badge "ATTACK ACTIVE" se attack_progress negli ultimi 30s

### API da aggiungere a dashboard.py
- GET /logs/tail?limit=50 → ultimi N eventi JSON
- POST /nodes/<name>/configure → avvia/spegne + configura container
- GET /status → stato sintetico (victim attiva, attacco attivo, n eventi)

### Task priorità
1. RULES.md — DONE
2. API /logs/tail e /status in dashboard.py
3. Rifacimento HTML/CSS/JS della pagina principale
4. Modali interattive per ogni nodo
5. Badge attacco attivo
6. (futuro) Alert panel
