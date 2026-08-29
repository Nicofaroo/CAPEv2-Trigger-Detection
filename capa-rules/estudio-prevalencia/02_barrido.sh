#!/bin/bash

set -uo pipefail

GRUPO="${1:-malware}"
source "$(dirname "$0")/config.sh"

CORPUS="$BASE/corpus/$GRUPO"
JSONDIR="$BASE/out/json/$GRUPO"
LOGDIR="$BASE/out/log/$GRUPO"
ESTADO="$BASE/out/estado_$GRUPO.csv"

mkdir -p "$JSONDIR" "$LOGDIR"
[[ -f "$ESTADO" ]] || echo "sha256,codigo_salida,segundos" > "$ESTADO"

TOTAL=$(find "$CORPUS" -type f | wc -l)
echo "[*] Grupo      : $GRUPO"
echo "[*] Corpus     : $TOTAL muestras en $CORPUS"
echo "[*] Paralelismo: $JOBS hilos, timeout $TIMEOUT_S s por muestra"
echo ""

analizar_una() {
    local f="$1"
    local sha; sha=$(basename "$f")
    local out="$JSONDIR/$sha.json"

    if [[ -s "$out" ]]; then
        return 0
    fi

    local t0; t0=$(date +%s)
    timeout "$TIMEOUT_S" "$CAPA_BIN" -j -r "$RULES_DIR" "$f" \
        > "$out" 2> "$LOGDIR/$sha.err"
    local rc=$?
    local t1; t1=$(date +%s)

    if [[ $rc -ne 0 ]] && [[ ! -s "$out" ]]; then
        rm -f "$out"
    fi
    [[ -s "$LOGDIR/$sha.err" ]] || rm -f "$LOGDIR/$sha.err"

    echo "$sha,$rc,$((t1 - t0))" >> "$ESTADO"
}
export -f analizar_una
export JSONDIR LOGDIR ESTADO CAPA_BIN RULES_DIR TIMEOUT_S

find "$CORPUS" -type f -print0 \
  | xargs -0 -P "$JOBS" -I{} bash -c 'analizar_una "$@"' _ {}

echo ""
echo "==== RESUMEN DEL BARRIDO ($GRUPO) ===="
HECHOS=$(find "$JSONDIR" -name '*.json' -size +0 | wc -l)
echo "JSON generados : $HECHOS / $TOTAL"
if [[ -f "$ESTADO" ]]; then
    echo "Timeouts (124) : $(awk -F, '$2==124' "$ESTADO" | wc -l)"
    echo "Otros errores  : $(awk -F, 'NR>1 && $2!=0 && $2!=124' "$ESTADO" | wc -l)"
    echo "Tiempo medio   : $(awk -F, 'NR>1 && $2==0 {s+=$3; n++} END {if(n) printf "%.1f s", s/n}' "$ESTADO")"
fi