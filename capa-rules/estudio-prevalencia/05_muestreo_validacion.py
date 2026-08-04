#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
05_muestreo_validacion.py - Extrae la submuestra para verificacion manual.

Sin esto, todos los porcentajes del estudio son "lo que dicen mis reglas", no
"lo que hay". Con esto puedes estimar precision y recall y, por tanto, corregir
la prevalencia observada.

Genera $BASE/out/validacion.csv con 25 positivos y 25 negativos elegidos al
azar (semilla fija para que sea reproducible), y una columna vacia que rellenas
tu tras mirar cada binario en Ghidra.

Como rellenar la columna 'veredicto':
    VP  verdadero positivo  - la regla casa y el mecanismo RTT esta de verdad
    FP  falso positivo      - la regla casa pero la API se usa para otra cosa
    VN  verdadero negativo  - la regla no casa y no hay mecanismo RTT
    FN  falso negativo      - la regla no casa pero SI hay mecanismo RTT

Que mirar en Ghidra para decidir:
    - GetCursorPos dentro de un bucle, con comparacion entre lecturas -> VP
    - GetCursorPos suelto para posicionar un menu o una ventana        -> FP
    - MessageBox cuyo valor de retorno condiciona el flujo             -> VP
    - MessageBox que solo informa de un error y sigue igual            -> FP
    - GetAsyncKeyState en bucle sondeando teclas                       -> VP
      (ojo: tambien lo usan los keyloggers; eso es captura, no RTT.
       Si el resultado no condiciona la ejecucion, es FP para tu regla)
"""

import csv
import os
import random
from pathlib import Path

BASE = Path(os.environ.get("BASE", Path.home() / "tfg-prevalencia"))
N_POR_CLASE = 25
SEMILLA = 20260727          # fija: el muestreo debe ser reproducible
UMBRAL_IMPORTS = 20         # mismo umbral de aplicabilidad que en 04_analisis.py


def main():
    ruta = BASE / "out" / "resultados.csv"
    if not ruta.exists():
        raise SystemExit(f"[!] No existe {ruta}. Ejecuta antes 03_parsear.py")

    with open(ruta, newline="", encoding="utf-8") as f:
        todas = [r for r in csv.DictReader(f)
                 if r["grupo"] == "malware" and r["estado"] == "ok"]

    def n_imp(r):
        try:
            return int(r.get("n_imports") or 0)
        except ValueError:
            return 0

    # SOLO el estrato aplicable. En las muestras con la tabla de importaciones
    # practicamente vacia no es posible emitir un veredicto: no se puede
    # distinguir "no implementa el mecanismo" de "lo implementa pero resuelve
    # las APIs en tiempo de ejecucion y no se ve". Incluirlas convertiria la
    # mayoria de los negativos en casos no verificables.
    filas = [r for r in todas if n_imp(r) >= UMBRAL_IMPORTS]
    descartadas = len(todas) - len(filas)

    positivos = [r for r in filas if r["rtt_any"] == "1"]
    negativos = [r for r in filas if r["rtt_any"] == "0"]

    print(f"[*] Malware analizado          : {len(todas)}")
    print(f"[*] Excluidas por < {UMBRAL_IMPORTS} imports : {descartadas} (no verificables)")
    print(f"[*] Universo de muestreo       : {len(filas)}")
    print(f"    {len(positivos)} positivos, {len(negativos)} negativos")
    if len(positivos) < N_POR_CLASE or len(negativos) < N_POR_CLASE:
        print("[=] Aviso: alguna clase tiene menos de 25 muestras. Cojo las que haya.")

    rnd = random.Random(SEMILLA)
    sel = (rnd.sample(positivos, min(N_POR_CLASE, len(positivos))) +
           rnd.sample(negativos, min(N_POR_CLASE, len(negativos))))
    rnd.shuffle(sel)        # mezclo para no revisar en bloque y sesgarme

    campos = ["sha256", "familia", "n_imports", "prediccion_regla",
              "mecanismos_detectados", "veredicto", "mecanismo_real", "notas"]

    salida = BASE / "out" / "validacion.csv"
    with open(salida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for r in sel:
            mecs = [n for n, c in [("cursor", "rtt_cursor"), ("teclado", "rtt_teclado"),
                                   ("dialogo", "rtt_dialogo"), ("inactividad", "rtt_inactividad")]
                    if r[c] == "1"]
            w.writerow({
                "sha256": r["sha256"],
                "familia": r["familia"],
                "n_imports": r.get("n_imports", ""),
                "prediccion_regla": "RTT" if r["rtt_any"] == "1" else "sin RTT",
                "mecanismos_detectados": ";".join(mecs),
                "veredicto": "",          # <-- lo rellenas tu: VP / FP / VN / FN
                "mecanismo_real": "",
                "notas": "",
            })

    print("")
    print(f"[+] {len(sel)} muestras para revisar en {salida}")
    print(f"    Los binarios estan en {BASE / 'corpus' / 'malware'}/<sha256>")
    print("")
    print("Cuando lo tengas relleno, calcula:")
    print("  Precision = VP / (VP + FP)")
    print("  Recall    = VP / (VP + FN)")
    print("Y corrige la prevalencia observada: p_real ~ (p_obs - FPR) / (TPR - FPR)")


if __name__ == "__main__":
    main()
