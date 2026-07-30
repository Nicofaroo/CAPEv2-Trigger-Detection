#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
01b_metadatos.py - Completa familia y fecha consultando la API de MalwareBazaar
                   SOLO para los hashes que hay en el corpus.

Alternativa al volcado completo (full.csv), que son >1.000.000 de muestras
cuando aqui solo hacen falta ~1.800. Actualiza meta/corpus.csv en el sitio,
de modo que NO hay que volver a extraer los lotes.

Uso:
    export MB_KEY="tu-auth-key"
    python3 01b_metadatos.py

Opciones:
    --hilos N     consultas simultaneas (por defecto 4; no subir mucho, hay
                  politica de uso justo)
    --reintentos  numero de reintentos por hash ante error de red

Solo consulta los hashes cuya familia siga siendo 'sin_etiquetar', asi que se
puede relanzar sin repetir trabajo si se corta a mitad.
"""

import argparse
import csv
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = Path(os.environ.get("BASE", Path.home() / "tfg-prevalencia"))
ENDPOINTS = [
    "https://mb-api.abuse.ch/api/v1/",
    "https://mb-api.abuse.ch/api/v2/",
]

_lock = threading.Lock()
_hechas = 0


def consultar(sha256, clave, reintentos=3):
    """Devuelve dict con familia/first_seen/file_type, o None si no se sabe."""
    datos = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    for intento in range(reintentos):
        for url in ENDPOINTS:
            req = urllib.request.Request(url, data=datos, method="POST")
            req.add_header("Auth-Key", clave)
            req.add_header("User-Agent", "TFG-prevalencia-RTT/1.0")
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    doc = json.loads(r.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as e:
                if e.code in (429, 503):        # limite o saturacion: espero
                    time.sleep(5 * (intento + 1))
                    continue
                continue
            except Exception:
                continue

            if doc.get("query_status") != "ok":
                return None
            lista = doc.get("data") or []
            if not lista:
                return None
            d = lista[0]
            return {
                "familia": (d.get("signature") or "").strip() or "sin_etiquetar",
                "first_seen": (d.get("first_seen") or "").strip(),
                "file_type": (d.get("file_type") or "").strip(),
            }
        time.sleep(2 * (intento + 1))
    return None


def trabajador(cola, clave, resultados, total, reintentos):
    global _hechas
    while True:
        with _lock:
            if not cola:
                return
            sha = cola.pop()
        info = consultar(sha, clave, reintentos)
        with _lock:
            if info:
                resultados[sha] = info
            _hechas += 1
            if _hechas % 50 == 0 or _hechas == total:
                print(f"    {_hechas}/{total} consultados, "
                      f"{len(resultados)} con metadatos", flush=True)
        time.sleep(0.15)        # cortesia con la API


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hilos", type=int, default=4)
    ap.add_argument("--reintentos", type=int, default=3)
    args = ap.parse_args()

    clave = os.environ.get("MB_KEY", "").strip()
    if not clave:
        raise SystemExit("[!] Falta la Auth-Key. Haz:  read -s MB_KEY && export MB_KEY")

    ruta = BASE / "meta" / "corpus.csv"
    if not ruta.exists():
        raise SystemExit(f"[!] No existe {ruta}. Ejecuta antes 01_corpus.py")

    with open(ruta, newline="", encoding="utf-8") as f:
        lector = csv.DictReader(f)
        campos = lector.fieldnames
        filas = list(lector)

    pendientes = [r["sha256"] for r in filas
                  if r["grupo"] == "malware"
                  and r.get("familia", "") in ("", "sin_etiquetar")]

    if not pendientes:
        print("[=] No hay nada pendiente: todas las muestras ya tienen familia.")
        return

    print(f"[*] Consultando {len(pendientes)} hashes con {args.hilos} hilos ...")
    print("    (se puede cortar con Ctrl+C y relanzar; no repite lo ya hecho)")
    resultados = {}
    cola = list(pendientes)
    hilos = [threading.Thread(target=trabajador,
                              args=(cola, clave, resultados, len(pendientes), args.reintentos),
                              daemon=True)
             for _ in range(max(1, args.hilos))]
    t0 = time.time()
    for h in hilos:
        h.start()
    try:
        for h in hilos:
            h.join()
    except KeyboardInterrupt:
        print("\n[=] Interrumpido. Guardo lo obtenido hasta ahora.")

    # --- Volcar resultados ---
    for r in filas:
        info = resultados.get(r["sha256"])
        if info:
            r["familia"] = info["familia"]
            r["first_seen"] = info["first_seen"] or r.get("first_seen", "")
            if info["file_type"]:
                r["file_type"] = info["file_type"]

    with open(ruta, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)

    mal = [r for r in filas if r["grupo"] == "malware"]
    con = sum(1 for r in mal if r.get("familia") not in ("", "sin_etiquetar"))
    familias = {}
    for r in mal:
        fam = r.get("familia", "")
        if fam and fam != "sin_etiquetar":
            familias[fam] = familias.get(fam, 0) + 1

    print("")
    print(f"[+] {ruta} actualizado en {time.time()-t0:.0f} s")
    print(f"    Con etiqueta de familia: {con}/{len(mal)}")
    if familias:
        print("    Familias mas frecuentes:")
        for fam, n in sorted(familias.items(), key=lambda x: -x[1])[:10]:
            print(f"      {n:5d}  {fam}")


if __name__ == "__main__":
    main()
