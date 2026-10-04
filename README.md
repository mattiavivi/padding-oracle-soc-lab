# Padding Oracle SOC Lab

Laboratorio containerizzato con doppio focus:
- **Crypto Core**: attacco Padding Oracle su AES-CBC.
- **SOC Layer**: raccolta log, metriche e alerting.

## Documentazione
- [Architettura](./docs/architecture.md)
- [Architecture Decision Records (ADRs)](./docs/decisions/README.md)
- [Metodologia di Detection Engineering](./docs/detection_engineering_methodology.md)
- [Comandi utili](./docs/commands.md)
- [UI SOC](./docs/ui.md)

## Avvio rapido

```bash
chmod +x start.sh tests/smoke.sh
./start.sh up
./tests/smoke.sh
./start.sh run-attack
curl -s http://localhost:18090/alerts
```

## Switch varianti victim

```bash
./start.sh down && ./start.sh up-partial
./start.sh down && ./start.sh up-fixed
```

## Traffico benigno

```bash
./start.sh start-benign
```

## Crypto workbench

```bash
TOKEN=$(curl -s http://localhost:18080/sample_token | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')
python control/crypto_workbench.py --token-b64 "$TOKEN"
```
