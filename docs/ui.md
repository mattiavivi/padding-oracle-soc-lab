# UI SOC

La dashboard web gira sul servizio `soc-ui`.

## URL
- UI principale: `http://localhost:18091`
- Pannello Docker: `http://localhost:18091/docker`
- Pannello Log: `http://localhost:18091/logs`
- Pannello Alert: `http://localhost:18091/alerts`

## Funzioni
- `soc-ui` mantiene `soc` sempre attivo (non è possibile fermare `soc` separatamente dalla UI).
- Avvio/stop dei container workload: `victim-vuln`, `victim-partial`, `victim-fixed`, `benign-1`, `benign-2`, `attacker`.
- Esecuzione di:
  - attacco padding oracle,
  - traffico benigno.
- Visualizzazione di tutti gli host del lab nel grafo (attivi e spenti), con stato ON/OFF.
- Pulsante **Reset Test**: riporta il lab su `victim-vuln`, ferma workload attacker/benign e pulisce i log.
- All'avvio di `soc-ui`, i log JSONL vengono puliti automaticamente.
- Visualizzazione eventi JSONL per servizio, mode e scenario.
- Gestione soglie di alert via form.

## Avvio
```bash
cd /home/sysadmin/test/project/padding-oracle-soc-lab
docker compose up -d --build soc-ui
```

## Nota
Il servizio UI usa il socket Docker host per controllare i container del laboratorio.
