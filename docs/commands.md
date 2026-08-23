# Comandi utili

## Avvio
```bash
cd /home/sysadmin/test/project/padding-oracle-soc-lab
docker compose up -d --build soc victim-vuln
docker compose up -d --build soc-ui
```

## Stato
```bash
./control/scenario.sh status
docker compose ps
```

## Attivare varianti victim
```bash
./control/scenario.sh up-vuln
./control/scenario.sh up-partial
./control/scenario.sh up-fixed
```

## Traffico benigno
```bash
./control/scenario.sh start-benign
```

## Eseguire l’attacco
```bash
./control/scenario.sh run-attack
./control/scenario.sh run-attack http://victim-fixed:8080
```

## Verifica rapida
```bash
./tests/smoke.sh http://localhost:18080
curl -s http://localhost:18090/health
curl -s http://localhost:18090/metrics
curl -s http://localhost:18090/alerts
curl -s http://localhost:18091/
```

## Crypto workbench
```bash
TOKEN=$(curl -s http://localhost:18080/sample_token | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
python3 control/crypto_workbench.py --token-b64 "$TOKEN"
```

## Stop pulito
```bash
./control/scenario.sh down
# Se fermi soc-ui, la UI ferma automaticamente anche soc.
```

## Logs
```bash
tail -f runtime-logs/victim.jsonl
tail -f runtime-logs/attacker.jsonl
```
