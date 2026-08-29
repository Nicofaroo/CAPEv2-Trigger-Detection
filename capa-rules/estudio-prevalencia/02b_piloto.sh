#!/bin/bash

set -uo pipefail

N="${1:-20}"
TMO="${2:-600}"
HILOS="${3:-8}"

source "$(dirname "$0")/config.sh"

GRUPO=malware
CORPUS="$BASE/corpus/$GRUPO"
JSONDIR="$BASE/out/json/$GRUPO"
LOGDIR="$BASE/out/log/$GRUPO"
ESTADO="$BASE/out/estado_$GRUPO.csv"
PILOTO="$BASE/out/piloto_$(date +%Y%m%d_%H%M).csv"

[[ -f "$ESTADO" ]] || { echo "[!] No existe $ESTADO."; exit 1; }

mapfile -t EXPIRADAS < <(
    awk -F, 'NR>1 && $2==124 {print $1}' "$ESTADO" | sort -u | while read -r sha; do
        [[ -s "$JSONDIR/$sha.json" ]] || echo "$sha"
    done
)

TOTAL=${#EXPIRADAS[@]}
if [[ $TOTAL -eq 0 ]]; then
    echo "[=] No queda ningun timeout pendiente."
    exit 0
fi

mapfile -t SEL < <(printf '%s\n' "${EXPIRADAS[@]}" | sort | shuf -n "$N" --random-source=/dev/zero)

echo "=========================================================="
echo " PILOTO DE RECUPERACION"
echo "=========================================================="
echo "Timeouts pendientes : $TOTAL"
echo "Muestras del piloto : ${#SEL[@]}"
echo "Timeout             : $TMO s   (antes: 180 s)"
echo "Paralelismo         : $HILOS hilos"
echo ""
echo "Peor caso de duracion: $(( (${#SEL[@]} + HILOS - 1) / HILOS * TMO / 60 )) min"
echo ""

echo "sha256,codigo_salida,segundos" > "$PILOTO"

analizar_una() {
    local sha="$1"
    local out="$JSONDIR/$sha.json"
    [[ -s "$out" ]] && return 0
    local t0; t0=$(date +%s)
    timeout "$TMO" "$CAPA_BIN" -j -r "$RULES_DIR" "$CORPUS/$sha" \
        > "$out" 2> "$LOGDIR/$sha.err"
    local rc=$?
    local t1; t1=$(date +%s)
    [[ $rc -ne 0 ]] && [[ ! -s "$out" ]] && rm -f "$out"
    [[ -s "$LOGDIR/$sha.err" ]] || rm -f "$LOGDIR/$sha.err"
    echo "$sha,$rc,$((t1 - t0))" >> "$PILOTO"
    if [[ $rc -eq 0 ]]; then
        echo "  [OK]      $((t1 - t0))s  ${sha:0:16}"
    elif [[ $rc -eq 124 ]]; then
        echo "  [TIMEOUT]      ${sha:0:16}"
    else
        echo "  [ERROR $rc]    ${sha:0:16}"
    fi
}
export -f analizar_una
export JSONDIR LOGDIR CORPUS CAPA_BIN RULES_DIR TMO PILOTO

printf '%s\n' "${SEL[@]}" \
  | xargs -P "$HILOS" -I{} bash -c 'analizar_una "$@"' _ {}

OK=$(awk -F, 'NR>1 && $2==0' "$PILOTO" | wc -l)
TO=$(awk -F, 'NR>1 && $2==124' "$PILOTO" | wc -l)
ER=$(awk -F, 'NR>1 && $2!=0 && $2!=124' "$PILOTO" | wc -l)
MED=$(awk -F, 'NR>1 && $2==0 {s+=$3; n++} END {if(n) printf "%.0f", s/n; else print 0}' "$PILOTO")
NSEL=${#SEL[@]}

echo ""
echo "=========================================================="
echo " RESULTADO DEL PILOTO"
echo "=========================================================="
echo "Recuperadas   : $OK / $NSEL"
echo "Siguen fuera  : $TO timeouts, $ER errores"
[[ $OK -gt 0 ]] && echo "Tiempo medio  : $MED s"
echo ""

if [[ $NSEL -gt 0 ]]; then
    TASA=$(( 100 * OK / NSEL ))
    EST_REC=$(( TOTAL * OK / NSEL ))
    echo "Tasa de recuperacion estimada : $TASA %"
    echo "Muestras recuperables (aprox) : $EST_REC de $TOTAL"
    if [[ $OK -gt 0 ]]; then
        HORAS=$(awk -v t=$TOTAL -v m=$MED -v h=$HILOS 'BEGIN{printf "%.1f", t*m/h/3600}')
        echo "Duracion estimada 2a pasada   : ~$HORAS h (cota optimista)"
    fi
    echo ""
    if   [[ $TASA -ge 50 ]]; then
        echo "VEREDICTO: merece la pena. Se recupera mas de la mitad."
    elif [[ $TASA -ge 20 ]]; then
        echo "VEREDICTO: dudoso. Valora si el sesgo compensa las horas."
    else
        echo "VEREDICTO: no merece la pena."
        echo "  esas muestras son inanalizables estaticamente en tiempo razonable."
    fi
fi
echo ""
echo "Detalle en $PILOTO"