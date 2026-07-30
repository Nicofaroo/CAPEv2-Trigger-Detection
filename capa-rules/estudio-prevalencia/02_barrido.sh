#!/bin/bash
# ==============================================================================
# 02_barrido.sh - Pasa capa (reglas RTT + oficiales) sobre todo el corpus.
#
# Uso:  ./02_barrido.sh [malware|goodware]
#
# Guarda un JSON por muestra en $BASE/out/json/<grupo>/<sha256>.json y un
# registro de estado en $BASE/out/estado_<grupo>.csv con el codigo de salida
# de cada analisis (0 = ok, 124 = timeout, otro = error de capa).
#
# Es reanudable: si el JSON de una muestra ya existe y no esta vacio, se salta.
# Puedes cortar con Ctrl+C y relanzar sin perder trabajo.
# ==============================================================================

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

# --- Funcion que analiza UNA muestra (se exporta para que la vea xargs) ---
analizar_una() {
    local f="$1"
    local sha; sha=$(basename "$f")
    local out="$JSONDIR/$sha.json"

    # Reanudable: si ya hay un JSON no vacio, no repito
    if [[ -s "$out" ]]; then
        return 0
    fi

    local t0; t0=$(date +%s)
    timeout "$TIMEOUT_S" "$CAPA_BIN" -j -r "$RULES_DIR" "$f" \
        > "$out" 2> "$LOGDIR/$sha.err"
    local rc=$?
    local t1; t1=$(date +%s)

    # Si capa fallo, el JSON queda basura: lo borro para poder reintentar
    if [[ $rc -ne 0 ]] && [[ ! -s "$out" ]]; then
        rm -f "$out"
    fi
    # Si el .err esta vacio no me sirve de nada
    [[ -s "$LOGDIR/$sha.err" ]] || rm -f "$LOGDIR/$sha.err"

    echo "$sha,$rc,$((t1 - t0))" >> "$ESTADO"
}
export -f analizar_una
export JSONDIR LOGDIR ESTADO CAPA_BIN RULES_DIR TIMEOUT_S

# --- Lanzamiento en paralelo ---
find "$CORPUS" -type f -print0 \
  | xargs -0 -P "$JOBS" -I{} bash -c 'analizar_una "$@"' _ {}

# --- Resumen ---
echo ""
echo "==== RESUMEN DEL BARRIDO ($GRUPO) ===="
HECHOS=$(find "$JSONDIR" -name '*.json' -size +0 | wc -l)
echo "JSON generados : $HECHOS / $TOTAL"
if [[ -f "$ESTADO" ]]; then
    echo "Timeouts (124) : $(awk -F, '$2==124' "$ESTADO" | wc -l)"
    echo "Otros errores  : $(awk -F, 'NR>1 && $2!=0 && $2!=124' "$ESTADO" | wc -l)"
    echo "Tiempo medio   : $(awk -F, 'NR>1 && $2==0 {s+=$3; n++} END {if(n) printf "%.1f s", s/n}' "$ESTADO")"
fi
echo ""
echo "Siguiente paso: python3 03_parsear.py"
