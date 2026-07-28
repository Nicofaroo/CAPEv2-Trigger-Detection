#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
01_corpus.py - Construye el corpus a partir de los lotes diarios de MalwareBazaar.

Que hace:
  1. Extrae los ZIP de $BASE/zips/ (password 'infected'), manejando el caso de
     ZIP anidados (lote diario que contiene un ZIP por muestra).
  2. Filtra: se queda SOLO con PE32/PE32+ validos. Descarta lo demas.
  3. Deduplica por SHA-256 y renombra cada fichero a su hash.
  4. Cruza con el CSV de metadatos de MalwareBazaar para obtener familia,
     fecha de primera aparicion y tipo declarado.
  5. Escribe $BASE/meta/corpus.csv con una fila por muestra.

Uso:
    python3 01_corpus.py                 # procesa malware
    python3 01_corpus.py --grupo goodware --origen /ruta/a/system32_extraido

Requisitos: 7z en el PATH. pefile es opcional (mejora el filtrado y anade
columnas); si no esta, se hace un filtrado mas basico leyendo la cabecera PE
a mano.
"""

import argparse
import csv
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import pefile
    HAY_PEFILE = True
except ImportError:
    HAY_PEFILE = False

BASE = Path(os.environ.get("BASE", Path.home() / "tfg-prevalencia"))
MAX_MB = 50          # descarto ficheros enormes: capa tarda muchisimo y aportan poco
SEMILLA = 20260727   # fija: el submuestreo debe ser reproducible


# --------------------------------------------------------------- utilidades ---

def sha256_de(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def info_pe(ruta):
    """Devuelve un dict con datos del PE, o None si no es un PE valido."""
    try:
        with open(ruta, "rb") as f:
            cabecera = f.read(0x40)
        if len(cabecera) < 0x40 or cabecera[:2] != b"MZ":
            return None
    except OSError:
        return None

    if HAY_PEFILE:
        try:
            pe = pefile.PE(str(ruta), fast_load=True)
        except Exception:
            return None
        maquina = pe.FILE_HEADER.Machine
        arch = {0x14c: "x86", 0x8664: "x64", 0x1c0: "arm", 0xaa64: "arm64"}.get(maquina, hex(maquina))
        es_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        # imphash es util para agrupar variantes; puede fallar en muestras rotas
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imph = pe.get_imphash()
            n_imports = sum(len(d.imports) for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        except Exception:
            imph, n_imports = "", 0
        pe.close()
        return {"arch": arch, "es_dll": int(es_dll), "imphash": imph, "n_imports": n_imports}

    # --- Fallback sin pefile: leo e_lfanew y la Machine a mano ---
    try:
        with open(ruta, "rb") as f:
            f.seek(0x3C)
            e_lfanew = struct.unpack("<I", f.read(4))[0]
            f.seek(e_lfanew)
            if f.read(4) != b"PE\0\0":
                return None
            maquina = struct.unpack("<H", f.read(2))[0]
            f.seek(e_lfanew + 22)
            caracteristicas = struct.unpack("<H", f.read(2))[0]
    except Exception:
        return None
    arch = {0x14c: "x86", 0x8664: "x64", 0x1c0: "arm", 0xaa64: "arm64"}.get(maquina, hex(maquina))
    return {"arch": arch, "es_dll": int(bool(caracteristicas & 0x2000)),
            "imphash": "", "n_imports": 0}


def extraer_recursivo(zip_path, destino, password="infected", profundidad=0):
    """Extrae un ZIP y, si dentro hay mas ZIP, los extrae tambien (1 nivel)."""
    if profundidad > 2:
        return
    cmd = ["7z", "x", "-y", f"-p{password}", f"-o{destino}", str(zip_path)]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        print(f"    [!] 7z fallo en {zip_path.name}: {r.stderr.decode(errors='replace')[:200]}")
        return
    # Si el lote diario contiene un ZIP por muestra, los abro tambien
    for hijo in list(Path(destino).rglob("*.zip")):
        sub = Path(tempfile.mkdtemp(dir=destino))
        extraer_recursivo(hijo, sub, password, profundidad + 1)
        hijo.unlink(missing_ok=True)


def cargar_metadatos(ruta_csv):
    """
    Lee el CSV de MalwareBazaar. El fichero lleva lineas de comentario que
    empiezan por '#' y campos entrecomillados separados por ', '.
    Devuelve dict: sha256 -> {familia, first_seen, file_type}
    """
    meta = {}
    if not ruta_csv.exists():
        print(f"[=] No hay metadatos en {ruta_csv}: seguire sin familia ni fecha.")
        return meta

    columnas = ["first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter",
                "file_name", "file_type_guess", "mime_type", "signature", "clamav",
                "vtpercent", "imphash", "ssdeep", "tlsh"]

    with open(ruta_csv, "r", encoding="utf-8", errors="replace") as f:
        lineas = (l for l in f if not l.lstrip().startswith("#") and l.strip())
        lector = csv.reader(lineas, skipinitialspace=True)
        for fila in lector:
            if len(fila) < 9:
                continue
            d = dict(zip(columnas, fila))
            sha = d.get("sha256_hash", "").strip().lower()
            if len(sha) != 64:
                continue
            meta[sha] = {
                "familia": (d.get("signature") or "").strip() or "sin_etiquetar",
                "first_seen": (d.get("first_seen_utc") or "").strip(),
                "file_type": (d.get("file_type_guess") or "").strip(),
            }
    print(f"[+] Metadatos cargados: {len(meta)} entradas.")
    return meta


# -------------------------------------------------------------------- main ---

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--grupo", default="malware", choices=["malware", "goodware"])
    ap.add_argument("--origen", default=None,
                    help="Directorio con binarios ya extraidos (para goodware). "
                         "Si no se indica, se procesan los ZIP de $BASE/zips/")
    ap.add_argument("--max", type=int, default=None, metavar="N",
                    help="Submuestreo aleatorio de N muestras (semilla fija). "
                         "Sin esta opcion se procesan todas.")
    ap.add_argument("--tmpdir", default=None,
                    help="Directorio temporal para la extraccion. Por defecto "
                         "$BASE/tmp, para no llenar /tmp si esta en RAM.")
    ap.add_argument("--solo-contar", action="store_true",
                    help="Extrae y cuenta cuantos PE unicos hay, sin copiar nada "
                         "al corpus. Util para dimensionar antes de decidir.")
    args = ap.parse_args()

    destino_corpus = BASE / "corpus" / args.grupo
    destino_corpus.mkdir(parents=True, exist_ok=True)
    meta = cargar_metadatos(BASE / "meta" / "full.csv") if args.grupo == "malware" else {}

    # --- Reunir los ficheros candidatos ---
    tmp = None
    if args.origen:
        raiz = Path(args.origen)
        candidatos = [p for p in raiz.rglob("*") if p.is_file()]
    else:
        raiz_tmp = Path(args.tmpdir) if args.tmpdir else (BASE / "tmp")
        raiz_tmp.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="corpus_", dir=str(raiz_tmp)))
        zips = sorted((BASE / "zips").glob("*.zip"))
        if not zips:
            print(f"[!] No hay ZIP en {BASE/'zips'}. Descargalos primero.")
            sys.exit(1)
        print(f"[*] Extrayendo {len(zips)} lotes ...")
        for z in zips:
            print(f"  - {z.name}")
            sub = tmp / z.stem
            sub.mkdir(parents=True, exist_ok=True)
            extraer_recursivo(z, sub)
        candidatos = [p for p in tmp.rglob("*") if p.is_file()]

    print(f"[*] {len(candidatos)} ficheros extraidos. Filtrando PE y deduplicando ...")

    filas, vistos = [], set()
    reservados = []          # PE unicos encontrados, antes de decidir cuales copiar
    descartes = {"no_pe": 0, "duplicado": 0, "grande": 0, "vacio": 0}

    for p in candidatos:
        try:
            tam = p.stat().st_size
        except OSError:
            continue
        if tam == 0:
            descartes["vacio"] += 1
            continue
        if tam > MAX_MB * 1024 * 1024:
            descartes["grande"] += 1
            continue
        info = info_pe(p)
        if info is None:
            descartes["no_pe"] += 1
            continue
        sha = sha256_de(p)
        if sha in vistos:
            descartes["duplicado"] += 1
            continue
        vistos.add(sha)
        reservados.append((p, sha, tam, info))

    # --- Submuestreo aleatorio reproducible ---
    universo = len(reservados)
    if args.max and universo > args.max:
        rnd = random.Random(SEMILLA)
        reservados = rnd.sample(reservados, args.max)
        print("")
        print(f"[*] PE unicos disponibles (universo) : {universo}")
        print(f"[*] Submuestreo aleatorio a          : {args.max} (semilla {SEMILLA})")
        print(f"[*] Fraccion de muestreo             : {100*args.max/universo:.1f} %")
        print("    Anota estas tres cifras: van en la seccion de metodologia.")

    if args.solo_contar:
        print("")
        print(f"[=] PE unicos disponibles: {len(vistos)}")
        print(f"    Descartes -> no PE: {descartes['no_pe']}, duplicados: "
              f"{descartes['duplicado']}, >{MAX_MB}MB: {descartes['grande']}, "
              f"vacios: {descartes['vacio']}")
        est_h = len(vistos) * 20 / 24 / 3600
        print(f"    Estimacion del barrido a 20 s/muestra con 24 hilos: {est_h:.1f} h")
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return

    for p, sha, tam, info in reservados:
        shutil.copy2(p, destino_corpus / sha)
        m = meta.get(sha, {})
        filas.append({
            "sha256": sha,
            "grupo": args.grupo,
            "tam_bytes": tam,
            "arch": info["arch"],
            "es_dll": info["es_dll"],
            "imphash": info["imphash"],
            "n_imports": info["n_imports"],
            "familia": m.get("familia", "goodware" if args.grupo == "goodware" else "sin_etiquetar"),
            "first_seen": m.get("first_seen", ""),
            "file_type": m.get("file_type", ""),
            "nombre_original": p.name,
        })

    # --- Escribir corpus.csv (acumulativo entre grupos) ---
    salida = BASE / "meta" / "corpus.csv"
    existentes = []
    if salida.exists():
        with open(salida, newline="", encoding="utf-8") as f:
            existentes = [r for r in csv.DictReader(f) if r.get("grupo") != args.grupo]

    campos = ["sha256", "grupo", "tam_bytes", "arch", "es_dll", "imphash",
              "n_imports", "familia", "first_seen", "file_type", "nombre_original"]
    with open(salida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for r in existentes:
            w.writerow({k: r.get(k, "") for k in campos})
        w.writerows(filas)

    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)

    print("")
    print(f"[+] Corpus '{args.grupo}': {len(filas)} PE unicos en {destino_corpus}")
    print(f"    Descartes -> no PE: {descartes['no_pe']}, duplicados: {descartes['duplicado']}, "
          f">{MAX_MB}MB: {descartes['grande']}, vacios: {descartes['vacio']}")
    con_familia = sum(1 for r in filas if r["familia"] not in ("sin_etiquetar", "goodware"))
    if args.grupo == "malware":
        print(f"    Con etiqueta de familia: {con_familia}/{len(filas)}")
    print(f"[+] Metadatos en {salida}")
    if not HAY_PEFILE:
        print("[=] Nota: sin pefile. Instala con 'pip install pefile' para imphash y n_imports.")


if __name__ == "__main__":
    main()
