# Architettura del laboratorio

## Obiettivo
Laboratorio containerizzato per mostrare:
- Padding Oracle Attack su AES-CBC.
- Raccolta log e detection in stile SOC.

## Servizi

| Servizio | Ruolo | Porta host |
|---|---|---|
| `victim-vuln` | Server AES-CBC con oracle evidente | `18080` |
| `victim-partial` | Server con leakage ridotto | `18081` |
| `victim-fixed` | Server mitigato | `18082` |
| `attacker` | Esegue l’attacco sul target scelto | n/a |
| `benign-1` / `benign-2` | Traffico legittimo di baseline | n/a |
| `soc` | Collector, metriche e alert | `18090` |
| `soc-ui` | Dashboard web SOC | `18091` |

## Flusso dati
1. Il client benigno o l’attaccante invia richieste al victim.
2. Il victim registra eventi JSONL nel volume condiviso `runtime-logs/`.
3. Il collector SOC legge gli eventi e calcola metriche/alert.
4. La UI operativa è sostituita da script shell leggeri in `control/`.

## File chiave
- `docker-compose.yml`: orchestration dei container.
- `victim/app.py`: endpoint `/encrypt`, `/decrypt`, `/sample_token`.
- `attacker/attack.py`: attacco e validazione oracle.
- `benign/benign_client.py`: baseline di traffico.
- `soc/collector.py`: `/health`, `/metrics`, `/alerts`.
- `soc/dashboard.py`: UI per Docker, log e alert.
- `control/scenario.sh`: comandi rapidi di scenario.
- `control/crypto_workbench.py`: lettura blocchi CBC e IV.
- `schemas/event_schema.json`: formato eventi.

## Log prodotti
- `victim.jsonl`
- `attacker.jsonl`
- `benign-1.jsonl`
- `benign-2.jsonl`

Tutti i log sono JSON line-oriented e pensati per analisi automatica.
