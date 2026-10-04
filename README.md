# Padding Oracle SOC Lab

Laboratorio didattico containerizzato per studiare la relazione tra:

- **Crittografia applicata**: padding-oracle attack e timing side-channel su AES-CBC.
- **Detection Engineering**: telemetria, correlazione SIEM, threat hunting e risposta automatica WAF/SOAR.

Il progetto è pensato per essere eseguito localmente in un ambiente controllato. Non utilizzarlo contro sistemi o dati per i quali non hai autorizzazione.

## Cosa dimostra

Il laboratorio mette a confronto tre modalità del servizio victim:

| Modalità | Comportamento |
| --- | --- |
| `vuln` | Espone un oracolo basato su errori di padding/MAC distinti. |
| `partial` | Nasconde l'errore applicativo, ma mantiene una differenza temporale osservabile. |
| `fixed` | Applica una mitigazione crittografica e un'elaborazione più uniforme. |

Durante gli scenari vengono raccolti eventi strutturati dal SOC Collector. Il motore di detection calcola metriche per IP ed endpoint, genera alert e può attivare il WAF applicativo con un blocco temporaneo.

## Architettura

```text
attacker / benign clients
          |
          v
      victim API  --->  SOC Collector / SIEM  --->  Dashboard SOC
          ^                       |
          |                       v
          +------------- WAF / SOAR response
```

Componenti principali:

- `victim/`: API AES-CBC con modalità vulnerabile, parziale e mitigata.
- `attacker/`: client dimostrativo per l'attacco padding oracle.
- `benign/`: generatore di traffico legittimo.
- `soc/`: ingestion degli eventi, detection, alert e dashboard.
- `common/`: primitive crittografiche, logging e query SIEM.
- `control/`: configurazione delle regole e crypto workbench.
- `schemas/`: schema JSON della telemetria.
- `tests/`: test unitari e scenari di integrazione.

## Requisiti

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Git
- `curl` per le verifiche rapide

Le dipendenze Python vengono installate nell'immagine Docker. Non sono necessari `node_modules` o una virtualenv locale per eseguire il laboratorio tramite Docker.

## Avvio rapido

Dalla directory del repository:

```bash
./start.sh up
./tests/smoke.sh
```

Il comando `up` avvia la modalità vulnerabile, il SOC Collector e la dashboard. Gli indirizzi locali sono:

| Servizio | URL |
| --- | --- |
| Victim API | <http://localhost:18080> |
| SOC Collector | <http://localhost:18090> |
| Dashboard SOC | <http://localhost:18091> |

## Eseguire gli scenari

Avviare traffico benigno:

```bash
./start.sh start-benign
```

Eseguire l'attacco dimostrativo:

```bash
./start.sh run-attack
```

Cambiare modalità del victim:

```bash
./start.sh down
./start.sh up-partial

./start.sh down
./start.sh up-fixed
```

Controllare lo stato e gli alert:

```bash
./start.sh status
curl -s http://localhost:18090/health
curl -s http://localhost:18090/metrics
curl -s http://localhost:18090/alerts
```

Per arrestare e rimuovere i container del laboratorio:

```bash
./start.sh down
```

## Crypto workbench

Per ottenere un token di esempio e usare il workbench:

```bash
TOKEN=$(curl -s http://localhost:18080/sample_token \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
python3 control/crypto_workbench.py --token-b64 "$TOKEN"
```

## Test

Con le dipendenze Python disponibili nell'ambiente locale:

```bash
pytest -v tests/
./tests/smoke.sh
```

## Documentazione

- [Architettura](docs/architecture.md)
- [Comandi operativi](docs/commands.md)
- [Metodologia di Detection Engineering](docs/detection_engineering_methodology.md)
- [Architecture Decision Records](docs/decisions/README.md)
- [Specifiche della UI SOC](docs/ui.md)

## Note sul repository

Log runtime, cache, virtualenv e dipendenze generate sono esclusi da Git tramite `.gitignore`. Le note interne di sviluppo (`RULES.md`, `docs/ideas/`, `docs/plans/` e `docs/tasks/`) restano disponibili localmente ma non vengono pubblicate nel repository.
