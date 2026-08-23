# Padding Oracle SOC Lab

Laboratorio containerizzato con doppio focus:
- **Crypto Core**: attacco Padding Oracle su AES-CBC.
- **SOC Layer**: raccolta log, metriche e alerting.

## Documentazione
- [Architettura](./docs/architecture.md)
- [Comandi utili](./docs/commands.md)
- [UI SOC](./docs/ui.md)

## Avvio rapido

```bash
cd /home/sysadmin/test/project/padding-oracle-soc-lab
chmod +x control/scenario.sh tests/smoke.sh
docker compose up -d --build soc-ui
./control/scenario.sh up-vuln
./tests/smoke.sh
./control/scenario.sh run-attack
curl -s http://localhost:18090/alerts
```

## Switch varianti victim

```bash
./control/scenario.sh down && ./control/scenario.sh up-partial
./control/scenario.sh down && ./control/scenario.sh up-fixed
```

## Traffico benigno

```bash
./control/scenario.sh start-benign
```

## Crypto workbench

```bash
TOKEN=$(curl -s http://localhost:18080/sample_token | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')
python control/crypto_workbench.py --token-b64 "$TOKEN"
```
