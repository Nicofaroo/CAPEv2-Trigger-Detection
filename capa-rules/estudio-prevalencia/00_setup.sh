#!/bin/bash
# ==============================================================================
# 00_setup.sh - Prepara el arbol de directorios y el arbol de reglas fusionado.
#
# Uso:  ./00_setup.sh <version_capa>
# Ej.:  ./00_setup.sh v9.4.0
#
# Que hace:
#   1. Crea la estructura de directorios del estudio.
#   2. Clona el repositorio oficial de reglas de capa en la MISMA version que
#      tu binario standalone (si las versiones no casan, capa aborta al
#      encontrar features que no conoce).
#   3. Copia TUS 5 reglas RTT dentro de ese arbol.
#   4. Verifica que capa carga el arbol fusionado sin errores.
#
# Por que fusionar en lugar de usar solo tus reglas: el binario standalone de
# capa lleva las reglas oficiales embebidas, pero si pasas -r las SUSTITUYE por
# las del directorio que indiques. Fusionando, una sola pasada te da tus reglas
# RTT y ademas las oficiales de empaquetado (anti-analysis/packer/*), que son la
# variable independiente de la pregunta RQ2.
# ==============================================================================

set -euo pipefail

CAPA_VER="${1:-}"
if [[ -z "$CAPA_VER" ]]; then
    echo "Uso: $0 <version_capa>   (ej: $0 v9.4.0)"
    echo "Averigua tu version con:  \$CAPA --version"
    exit 1
fi

# ------------------------------------------------------------------ Rutas ----
BASE="$HOME/tfg-prevalencia"
CAPA_BIN="${CAPA_BIN:-$HOME/Descargas/capa}"       # exporta CAPA_BIN si esta en otro sitio
MIS_REGLAS="${MIS_REGLAS:-$HOME/Escritorio/capa-rtt-rules}"

echo "[*] Base del estudio : $BASE"
echo "[*] Binario capa     : $CAPA_BIN"
echo "[*] Mis reglas RTT   : $MIS_REGLAS"
echo ""

# ------------------------------------------------------ Comprobaciones -------
for cmd in git 7z python3; do
    command -v "$cmd" >/dev/null || { echo "[!] Falta '$cmd'. Instala: sudo apt install git p7zip-full python3"; exit 1; }
done
[[ -x "$CAPA_BIN" ]] || { echo "[!] No encuentro el binario de capa en $CAPA_BIN"; exit 1; }
[[ -d "$MIS_REGLAS" ]] || { echo "[!] No encuentro tus reglas en $MIS_REGLAS"; exit 1; }

# ------------------------------------------------------- Directorios ---------
for d in bin zips meta rules \
         corpus/malware corpus/goodware \
         out/json/malware out/json/goodware \
         out/log out/tablas out/figuras; do
    mkdir -p "$BASE/$d"
done
echo "[+] Arbol de directorios creado."

# ------------------------------------------------- Arbol de reglas -----------
RULES_DIR="$BASE/rules/capa-rules-rtt"
if [[ -d "$RULES_DIR" ]]; then
    echo "[=] El arbol de reglas ya existe, no lo vuelvo a clonar."
else
    echo "[*] Clonando reglas oficiales de capa en la version $CAPA_VER ..."
    if ! git clone --depth 1 --branch "$CAPA_VER" https://github.com/mandiant/capa-rules.git "$RULES_DIR" 2>/dev/null; then
        echo "[!] No existe el tag '$CAPA_VER' en capa-rules. Clonando master."
        echo "[!] AVISO: si capa se queja de features desconocidas, busca el tag correcto en"
        echo "           https://github.com/mandiant/capa-rules/tags"
        git clone --depth 1 https://github.com/mandiant/capa-rules.git "$RULES_DIR"
    fi
fi

# ------------------------------------------------- Inyeccion de mis reglas ---
DEST="$RULES_DIR/anti-analysis/anti-sandbox/reverse-turing-test"
mkdir -p "$DEST"
cp -v "$MIS_REGLAS"/*.yml "$DEST/"
N_MIAS=$(ls -1 "$DEST"/*.yml | wc -l)
echo "[+] $N_MIAS reglas RTT propias inyectadas en el arbol."

# ------------------------------------------------- Verificacion --------------
echo ""
echo "[*] Verificando que capa carga el arbol fusionado ..."
TEST_BIN="$(ls "$BASE/corpus/malware"/* 2>/dev/null | head -1 || true)"
if [[ -z "$TEST_BIN" ]]; then
    # Sin corpus todavia: uso el propio binario de capa como PE de prueba? No es PE.
    # Uso cualquier .exe que tengas a mano; si no, aviso.
    echo "[=] Aun no hay corpus. Verifica manualmente cuando lo tengas con:"
    echo "    $CAPA_BIN -j -r $RULES_DIR <un_pe.exe> | head"
else
    if "$CAPA_BIN" -j -r "$RULES_DIR" "$TEST_BIN" >/dev/null 2>"$BASE/out/log/setup_test.err"; then
        echo "[+] capa carga el arbol correctamente."
    else
        echo "[!] capa ha fallado. Revisa $BASE/out/log/setup_test.err"
        echo "    Causa mas probable: version de reglas != version de capa."
        exit 1
    fi
fi

# ------------------------------------------------- Fichero de config ---------
cat > "$BASE/bin/config.sh" <<EOF
# Configuracion compartida por el resto de scripts. Editala si cambias rutas.
export BASE="$BASE"
export CAPA_BIN="$CAPA_BIN"
export RULES_DIR="$RULES_DIR"
export TIMEOUT_S=180          # segundos maximos por muestra
export JOBS=\$(nproc)          # hilos en paralelo
EOF
echo "[+] Config escrita en $BASE/bin/config.sh"

echo ""
echo "==== LISTO ===="
echo "Siguiente paso: descarga los lotes diarios de MalwareBazaar en $BASE/zips/"
echo "y el CSV de metadatos en $BASE/meta/full.csv"
