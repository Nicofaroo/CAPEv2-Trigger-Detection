#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
03_parsear.py - Convierte los JSON de capa en una tabla plana de resultados.

Salida: $BASE/out/resultados.csv, una fila por muestra con:
  - identificacion y metadatos (del corpus.csv)
  - una columna 0/1 por cada mecanismo RTT
  - rtt_any: 1 si casa cualquiera de los cuatro
  - empaquetado: 1 si capa dispara alguna regla del namespace anti-analysis/packer
  - packer: nombre de la regla de empaquetado que ha casado
  - n_funciones: numero de funciones que capa ha logrado analizar
    (proxy adicional de empaquetado: un PE empaquetado suele dar muy pocas)
  - estado: ok / timeout / error / sin_json
"""

import csv
import json
import os
from pathlib import Path

BASE = Path(os.environ.get("BASE", Path.home() / "tfg-prevalencia"))

# Nombres EXACTOS de tus reglas (campo meta.name de cada .yml)
REGLAS_RTT = {
    "query mouse cursor position":            "rtt_cursor",
    "query keyboard or mouse button state":   "rtt_teclado",
    "wait for dialog confirmation":           "rtt_dialogo",
    "query last user input time":             "rtt_inactividad",
    "install low-level input hook":           "rtt_hook",
    "query double click threshold":           "rtt_dobleclic",
    "reverse turing test mechanism":          "rtt_agregada",
}

# Los cinco mecanismos que cuentan para el indicador agregado. 'rtt_dobleclic'
# queda fuera a proposito: es exploratoria y su poder discriminante se decide
# con el grupo de control (ver T1).
MECANISMOS_NUCLEO = ("rtt_cursor", "rtt_teclado", "rtt_dialogo",
                     "rtt_inactividad", "rtt_hook")

NS_PACKER = "anti-analysis/packer"


def n_funciones(doc):
    """El sitio exacto cambia entre versiones de capa, asi que pruebo varios."""
    meta = doc.get("meta", {})
    analisis = meta.get("analysis", meta)
    fc = analisis.get("feature_counts", {})
    fn = fc.get("functions")
    if isinstance(fn, list):
        return len(fn)
    if isinstance(fn, int):
        return fn
    if isinstance(fn, dict):
        return len(fn)
    return -1


def parsear_json(ruta):
    """Devuelve (dict_de_flags, error_o_None)."""
    try:
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            doc = json.load(f)
    except Exception as e:
        return None, f"json_ilegible: {type(e).__name__}"

    reglas = doc.get("rules", {}) or {}
    fila = {col: 0 for col in REGLAS_RTT.values()}
    fila["empaquetado"] = 0
    fila["packer"] = ""
    fila["n_funciones"] = n_funciones(doc)
    fila["n_reglas_total"] = len(reglas)

    packers = []
    for nombre, cuerpo in reglas.items():
        if nombre in REGLAS_RTT:
            fila[REGLAS_RTT[nombre]] = 1
        ns = ((cuerpo or {}).get("meta", {}) or {}).get("namespace", "") or ""
        if ns.startswith(NS_PACKER):
            fila["empaquetado"] = 1
            packers.append(nombre)
    fila["packer"] = ";".join(sorted(set(packers)))

    # rtt_any lo calculo yo a partir de los cuatro mecanismos, sin depender de
    # que la regla agregada haya casado (asi es independiente y comprobable).
    fila["rtt_any"] = int(any(fila[c] for c in MECANISMOS_NUCLEO))
    fila["n_mecanismos"] = sum(fila[c] for c in MECANISMOS_NUCLEO)
    return fila, None


def main():
    corpus = {}
    ruta_corpus = BASE / "meta" / "corpus.csv"
    if not ruta_corpus.exists():
        raise SystemExit(f"[!] No existe {ruta_corpus}. Ejecuta antes 01_corpus.py")
    with open(ruta_corpus, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            corpus[r["sha256"]] = r

    # Codigos de salida del barrido
    estados = {}
    for grupo in ("malware", "goodware"):
        p = BASE / "out" / f"estado_{grupo}.csv"
        if p.exists():
            with open(p, newline="", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    estados[r["sha256"]] = r["codigo_salida"]

    filas = []
    contador = {"ok": 0, "timeout": 0, "error": 0, "sin_json": 0}

    for sha, info in corpus.items():
        grupo = info["grupo"]
        ruta = BASE / "out" / "json" / grupo / f"{sha}.json"
        base = {
            "sha256": sha,
            "grupo": grupo,
            "familia": info.get("familia", ""),
            "first_seen": info.get("first_seen", ""),
            "arch": info.get("arch", ""),
            "es_dll": info.get("es_dll", ""),
            "tam_bytes": info.get("tam_bytes", ""),
            "n_imports": info.get("n_imports", ""),
        }

        if not ruta.exists() or ruta.stat().st_size == 0:
            cod = estados.get(sha, "")
            estado = "timeout" if cod == "124" else ("error" if cod else "sin_json")
            contador[estado] += 1
            base.update({c: "" for c in list(REGLAS_RTT.values()) +
                         ["rtt_any", "n_mecanismos", "empaquetado", "packer",
                          "n_funciones", "n_reglas_total"]})
            base["estado"] = estado
            filas.append(base)
            continue

        flags, err = parsear_json(ruta)
        if err:
            contador["error"] += 1
            base.update({c: "" for c in list(REGLAS_RTT.values()) +
                         ["rtt_any", "n_mecanismos", "empaquetado", "packer",
                          "n_funciones", "n_reglas_total"]})
            base["estado"] = "error"
            filas.append(base)
            continue

        contador["ok"] += 1
        base.update(flags)
        base["estado"] = "ok"
        filas.append(base)

    campos = ["sha256", "grupo", "familia", "first_seen", "arch", "es_dll",
              "tam_bytes", "n_imports", "estado",
              "rtt_cursor", "rtt_teclado", "rtt_dialogo", "rtt_inactividad",
              "rtt_hook", "rtt_dobleclic", "rtt_agregada", "rtt_any",
              "n_mecanismos", "empaquetado", "packer", "n_funciones",
              "n_reglas_total"]

    salida = BASE / "out" / "resultados.csv"
    with open(salida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)

    print(f"[+] {len(filas)} filas escritas en {salida}")
    print(f"    ok: {contador['ok']}, timeout: {contador['timeout']}, "
          f"error: {contador['error']}, sin JSON: {contador['sin_json']}")
    print("")
    print("IMPORTANTE para la memoria: las muestras con estado != ok NO son")
    print("negativos, son datos ausentes. Excluyelas del denominador y declara")
    print("cuantas eran y por que.")


if __name__ == "__main__":
    main()
