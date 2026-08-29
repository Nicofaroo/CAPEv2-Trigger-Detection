#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os
import random
from pathlib import Path

BASE = Path(os.environ.get("BASE", Path.home() / "tfg-prevalencia"))
N_POR_CLASE = 25
SEMILLA = 20260727
UMBRAL_IMPORTS = 20


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

    filas = [r for r in todas if n_imp(r) >= UMBRAL_IMPORTS]
    descartadas = len(todas) - len(filas)

    positivos = [r for r in filas if r["rtt_any"] == "1"]
    negativos = [r for r in filas if r["rtt_any"] == "0"]

    print(f"[*] Malware analizado          : {len(todas)}")
    print(f"[*] Excluidas por < {UMBRAL_IMPORTS} imports : {descartadas}")
    print(f"[*] Universo de muestreo       : {len(filas)}")
    print(f"    {len(positivos)} positivos, {len(negativos)} negativos")
    if len(positivos) < N_POR_CLASE or len(negativos) < N_POR_CLASE:
        print("[=] Aviso: alguna clase tiene menos de 25 muestras.")

    rnd = random.Random(SEMILLA)
    sel = (rnd.sample(positivos, min(N_POR_CLASE, len(positivos))) +
           rnd.sample(negativos, min(N_POR_CLASE, len(negativos))))
    rnd.shuffle(sel)

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
                "veredicto": "",
                "mecanismo_real": "",
                "notas": "",
            })

    print("")
    print(f"[+] {len(sel)} muestras para revisar en {salida}")
    print(f"    Los binarios estan en {BASE / 'corpus' / 'malware'}/<sha256>")


if __name__ == "__main__":
    main()