#!/usr/bin/env bash
set -eu

# ── Helpers ─────────────────────────────────────────────────────────────────

SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
while [ -h "$SCRIPT_SOURCE" ]; do
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
COMPOSE="docker compose -f $ROOT_DIR/docker-compose.yml"

# Tutti i container "gestiti" (compresi quelli one-shot lanciati dalla UI)
ALL_CONTAINERS="victim-vuln victim-partial victim-fixed soc soc-ui attacker benign-1 benign-2"

_stop_all_dynamic() {
  # Ferma e rimuove anche i container one-shot con prefisso dinamico (benign-*, attacker-*)
  # che vengono creati dalla dashboard con auto_remove=False
  local stray
  stray=$(docker ps -a --format '{{.Names}}' 2>/dev/null \
    | grep -E '^(attacker|benign)-[a-f0-9]{8}$' || true)
  if [ -n "$stray" ]; then
    echo "→ Rimuovo container one-shot: $stray"
    # shellcheck disable=SC2086
    docker rm -f $stray 2>/dev/null || true
  fi
}

_remove_named() {
  # Rimuove i container fissi per nome (se esistono)
  for name in $ALL_CONTAINERS; do
    if docker inspect "$name" &>/dev/null; then
      echo "→ Rimuovo: $name"
      docker rm -f "$name" 2>/dev/null || true
    fi
  done
}

# ── Comandi ─────────────────────────────────────────────────────────────────

usage() {
  echo ""
  echo "  Padding Oracle SOC Lab — script di controllo"
  echo ""
  echo "  Utilizzo:"
  echo "    ./start.sh <comando> [opzioni]"
  echo ""
  echo "  Comandi di avvio:"
  echo "    up            Avvia: victim-vuln + soc + soc-ui  (setup base)"
  echo "    up-vuln       Avvia: soc + victim-vuln"
  echo "    up-partial    Avvia: soc + victim-partial"
  echo "    up-fixed      Avvia: soc + victim-fixed"
  echo "    up-ui         Ricrea e avvia solo soc-ui  (= restart-ui)"
  echo "    rebuild-all   Ricrea tutto da zero (build + recreate) e avvia soc + victim-vuln + soc-ui"
  echo "    start-benign  Avvia: benign-1 + benign-2"
  echo "    run-attack    Esegue un attacco one-shot (--target <url> opzionale)"
  echo ""
  echo "  Comandi di gestione:"
  echo "    restart-ui    Ferma, rimuove e ricrea il container soc-ui"
  echo "    status        Mostra stato di tutti i container"
  echo "    down          Ferma e RIMUOVE tutti i container (compose + one-shot)"
  echo "    clean-all     Pulizia totale lab: stop/rimozione SOLO risorse del progetto (no prune globale)"
  echo ""
}

CMD="${1:-}"
if [ -z "$CMD" ]; then
  usage
  exit 1
fi

case "$CMD" in

  # ── Setup completo base ──────────────────────────────────────────────────
  up)
    $COMPOSE up -d soc victim-vuln soc-ui
    echo ""
    echo "✅  Lab avviato:"
    echo "    Dashboard UI → http://localhost:18091"
    echo "    SOC Collector → http://localhost:18090"
    echo "    Victim (vuln) → http://localhost:18080"
    ;;

  # ── Varianti vittima ─────────────────────────────────────────────────────
  up-vuln)
    $COMPOSE up -d soc victim-vuln
    ;;

  up-partial)
    $COMPOSE up -d soc victim-partial
    ;;

  up-fixed)
    $COMPOSE up -d soc victim-fixed
    ;;

  # ── UI: rimuovi e ricrea ─────────────────────────────────────────────────
  up-ui | restart-ui)
    echo "→ Fermo e rimuovo il container soc-ui..."
    docker rm -f soc-ui 2>/dev/null || true
    echo "→ Ricreo soc-ui con l'immagine aggiornata..."
    $COMPOSE up -d --no-deps --force-recreate soc-ui
    echo ""
    echo "✅  soc-ui riavviato → http://localhost:18091"
    ;;

  # ── Rebuild totale lab ───────────────────────────────────────────────────
  rebuild-all)
    echo "→ Pulizia completa del lab..."
    $COMPOSE down --remove-orphans --volumes
    _stop_all_dynamic
    _remove_named
    echo "→ Ricostruisco immagini e ricreo i container core..."
    $COMPOSE build --no-cache
    $COMPOSE up -d --force-recreate soc victim-vuln soc-ui
    echo ""
    echo "✅  Rebuild completato:"
    echo "    Dashboard UI → http://localhost:18091"
    echo "    SOC Collector → http://localhost:18090"
    echo "    Victim (vuln) → http://localhost:18080"
    ;;

  # ── Traffico benigno ─────────────────────────────────────────────────────
  start-benign)
    $COMPOSE up -d benign-1 benign-2
    ;;

  # ── Attacco one-shot ─────────────────────────────────────────────────────
  run-attack)
    TARGET="${2:-http://victim-vuln:8080}"
    $COMPOSE run --rm attacker --target "$TARGET"
    ;;

  # ── Stato ────────────────────────────────────────────────────────────────
  status)
    $COMPOSE ps
    echo ""
    echo "Container one-shot attivi:"
    docker ps --format '  {{.Names}}  [{{.Status}}]' \
      | grep -E '(attacker|benign)-[a-f0-9]{8}' || echo "  (nessuno)"
    ;;

  # ── Spegni e rimuovi tutto ───────────────────────────────────────────────
  down)
    echo "→ Fermo e rimuovo container docker-compose..."
    $COMPOSE down --remove-orphans
    echo "→ Cerco container one-shot della UI..."
    _stop_all_dynamic
    echo "→ Rimuovo eventuali container fissi rimasti..."
    _remove_named
    echo ""
    echo "✅  Tutti i container rimossi."
    ;;

  # ── Pulizia totale risorse progetto ─────────────────────────────────────
  clean-all)
    echo "→ Fermo e rimuovo container docker-compose..."
    $COMPOSE down --remove-orphans --volumes
    echo "→ Cerco container one-shot della UI..."
    _stop_all_dynamic
    echo "→ Rimuovo eventuali container fissi rimasti..."
    _remove_named
    echo "→ Rimuovo immagine del progetto (se presente): padding-oracle-soc-lab-base"
    docker rmi padding-oracle-soc-lab-base 2>/dev/null || true
    echo "→ Rimuovo network del progetto (se presente): padding-oracle-soc-lab_default"
    docker network rm padding-oracle-soc-lab_default 2>/dev/null || true
    echo ""
    echo "✅  Pulizia totale completata."
    ;;

  *)
    echo "Comando sconosciuto: '$CMD'"
    usage
    exit 1
    ;;
esac
