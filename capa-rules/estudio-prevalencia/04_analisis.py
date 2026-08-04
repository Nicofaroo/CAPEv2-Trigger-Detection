#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
04_analisis.py - Genera las tablas y figuras del estudio de prevalencia.

Produce en $BASE/out/tablas/ (CSV + Markdown listos para pegar en la memoria):
  T1  Prevalencia por mecanismo, malware vs goodware, con IC de Wilson y lift
  T2  Matriz de co-ocurrencia entre mecanismos
  T3  RTT x empaquetado (la tabla que justifica el modulo dinamico)
  T4  Prevalencia por familia (top N)
  T5  Evolucion temporal por año
  T6  Cobertura del barrido (estados)

Y en $BASE/out/figuras/: dos graficas en PDF (vectorial, para LaTeX).
"""

import os
from pathlib import Path

import numpy as np
import pandas as pd

BASE = Path(os.environ.get("BASE", Path.home() / "tfg-prevalencia"))
TABLAS = BASE / "out" / "tablas"
FIGURAS = BASE / "out" / "figuras"
TABLAS.mkdir(parents=True, exist_ok=True)
FIGURAS.mkdir(parents=True, exist_ok=True)

MECANISMOS = {
    "rtt_cursor": "Posicion del cursor",
    "rtt_teclado": "Estado de teclado/raton",
    "rtt_dialogo": "Confirmacion de dialogo",
    "rtt_inactividad": "Tiempo de inactividad",
    "rtt_hook": "Hook de entrada de bajo nivel",
    "rtt_dobleclic": "Umbral de doble clic (exploratoria)",
    "rtt_any": "Cualquier mecanismo RTT (agregado)",
}

# Los que entran en el agregado. La exploratoria se mide pero no suma.
NUCLEO = ["rtt_cursor", "rtt_teclado", "rtt_dialogo", "rtt_inactividad", "rtt_hook"]
TOP_FAMILIAS = 20

# Umbral de aplicabilidad: por debajo de este numero de importaciones se considera
# que la tabla de importaciones no aporta informacion suficiente para que las
# reglas basadas en APIs puedan pronunciarse.
UMBRAL_IMPORTS = 20


# ------------------------------------------------------------ estadistica ---

def wilson(exitos, n, z=1.96):
    """Intervalo de confianza de Wilson al 95%. Correcto tambien con p cerca de 0 o 1,
    a diferencia del intervalo normal, que es el que suele salir mal en estos casos."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = exitos / n
    d = 1 + z**2 / n
    centro = (p + z**2 / (2 * n)) / d
    margen = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / d
    return (max(0.0, centro - margen), min(1.0, centro + margen))


def guardar(df, nombre, titulo, nota=""):
    df.to_csv(TABLAS / f"{nombre}.csv", index=False)
    with open(TABLAS / f"{nombre}.md", "w", encoding="utf-8") as f:
        f.write(f"### {titulo}\n\n")
        f.write(df.to_markdown(index=False))
        if nota:
            f.write(f"\n\n_{nota}_\n")
    print(f"  [+] {nombre}: {titulo}")


# ------------------------------------------------------------------- main ---

def main():
    ruta = BASE / "out" / "resultados.csv"
    if not ruta.exists():
        raise SystemExit(f"[!] No existe {ruta}. Ejecuta antes 03_parsear.py")

    todo = pd.read_csv(ruta)

    # T6 - cobertura primero: hay que saber sobre que se analiza
    cob = (todo.groupby(["grupo", "estado"]).size()
           .reset_index(name="n").pivot(index="grupo", columns="estado", values="n")
           .fillna(0).astype(int).reset_index())
    guardar(cob, "T6_cobertura", "Cobertura del barrido",
            "Solo las filas con estado 'ok' entran en el resto del analisis.")

    # A partir de aqui, SOLO analisis completados
    df = todo[todo["estado"] == "ok"].copy()
    for c in list(MECANISMOS) + ["empaquetado", "n_mecanismos", "n_funciones", "n_imports"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)

    mal = df[df["grupo"] == "malware"]
    good = df[df["grupo"] == "goodware"]
    print(f"[*] Analizando {len(mal)} muestras de malware y {len(good)} de control.\n")

    # ---------------------------------------------------------------- T1 ----
    filas = []
    for col, nombre in MECANISMOS.items():
        km, nm = int(mal[col].sum()), len(mal)
        kg, ng = int(good[col].sum()), len(good)
        pm = km / nm if nm else float("nan")
        pg = kg / ng if ng else float("nan")
        lo_m, hi_m = wilson(km, nm)
        lo_g, hi_g = wilson(kg, ng)
        filas.append({
            "Mecanismo": nombre,
            "Malware n": km,
            "Malware %": round(100 * pm, 1),
            "IC95 malware": f"[{100*lo_m:.1f}, {100*hi_m:.1f}]",
            "Control n": kg,
            "Control %": round(100 * pg, 1),
            "IC95 control": f"[{100*lo_g:.1f}, {100*hi_g:.1f}]",
            "Lift": round(pm / pg, 1) if pg and pg > 0 else "inf",
            "En agregado": "si" if col in NUCLEO else ("-" if col == "rtt_any" else "NO"),
        })
    guardar(pd.DataFrame(filas), "T1_prevalencia",
            "Prevalencia por mecanismo RTT (corpus completo)",
            "Lift = prevalencia en malware / prevalencia en el grupo de control. "
            "Un lift proximo a 1 indica que el indicador NO discrimina. ATENCION: esta "
            "tabla promedia sobre muestras en las que el instrumento no es aplicable "
            "(ver T3), por lo que subestima la prevalencia real en el malware. La "
            "comparacion valida es la de T1b.")

    # --- T1b: la misma tabla restringida al estrato donde el instrumento aplica ---
    ma = mal[mal["n_imports"] >= UMBRAL_IMPORTS]
    ga = good[good["n_imports"] >= UMBRAL_IMPORTS]
    filas_b = []
    for col, nombre in MECANISMOS.items():
        km, nm = int(ma[col].sum()), len(ma)
        kg, ng = int(ga[col].sum()), len(ga)
        pm = km / nm if nm else float("nan")
        pg = kg / ng if ng else float("nan")
        lo_m, hi_m = wilson(km, nm)
        lo_g, hi_g = wilson(kg, ng)
        filas_b.append({
            "Mecanismo": nombre,
            "Malware n": km,
            "Malware %": round(100 * pm, 1),
            "IC95 malware": f"[{100*lo_m:.1f}, {100*hi_m:.1f}]",
            "Control n": kg,
            "Control %": round(100 * pg, 1),
            "IC95 control": f"[{100*lo_g:.1f}, {100*hi_g:.1f}]",
            "Lift": round(pm / pg, 1) if pg and pg > 0 else "inf",
            "En agregado": "si" if col in NUCLEO else ("-" if col == "rtt_any" else "NO"),
        })
    guardar(pd.DataFrame(filas_b), "T1b_prevalencia_aplicable",
            f"Prevalencia por mecanismo RTT (estrato aplicable, >= {UMBRAL_IMPORTS} importaciones)",
            f"Restringida a las muestras cuya tabla de importaciones permite que las "
            f"reglas se pronuncien: {len(ma)} de malware y {len(ga)} de control. Es la "
            "comparacion metodologicamente valida entre ambos grupos.")

    # ---------------------------------------------------------------- T2 ----
    cols4 = NUCLEO
    m = pd.DataFrame(index=[MECANISMOS[c] for c in cols4],
                     columns=[MECANISMOS[c] for c in cols4], dtype=int)
    for a in cols4:
        for b in cols4:
            m.loc[MECANISMOS[a], MECANISMOS[b]] = int(((mal[a] == 1) & (mal[b] == 1)).sum())
    m = m.reset_index().rename(columns={"index": "Mecanismo"})
    guardar(m, "T2_coocurrencia", "Co-ocurrencia de mecanismos (solo malware)",
            "La diagonal es el total de cada mecanismo. Fuera de la diagonal, "
            "muestras que implementan ambos.")

    reparto = (mal["n_mecanismos"].value_counts().sort_index()
               .rename_axis("Nº de mecanismos").reset_index(name="Muestras"))
    reparto["%"] = (100 * reparto["Muestras"] / len(mal)).round(1)
    guardar(reparto, "T2b_reparto_mecanismos", "Nº de mecanismos RTT por muestra")

    # ---------------------------------------------------------------- T3 ----
    # LA TABLA CLAVE: aplicabilidad del instrumento.
    #
    # Las reglas RTT operan sobre la tabla de importaciones del PE. Una muestra
    # que resuelve sus APIs en tiempo de ejecucion (GetProcAddress) mantiene esa
    # tabla practicamente vacia, de modo que el nombre de la API nunca aparece
    # donde las reglas miran. En esas muestras la regla no puede pronunciarse:
    # un negativo NO significa ausencia del mecanismo, significa que el
    # instrumento no es aplicable.
    #
    # Por eso se estratifica por numero de importaciones y no por la deteccion
    # de empaquetado: esta ultima resulto poco informativa (capa no marca como
    # empaquetadas las muestras que solo ocultan sus importaciones), mientras
    # que n_imports mide directamente la condicion de aplicabilidad.

    # --- Distribucion de importaciones, para justificar el umbral ---
    dist = []
    for etiq, sub in [("malware", mal), ("control", good)]:
        if not len(sub):
            continue
        q = sub["n_imports"].quantile([0.10, 0.25, 0.50, 0.75, 0.90])
        dist.append({
            "Grupo": etiq, "n": len(sub),
            "p10": int(q.loc[0.10]), "p25": int(q.loc[0.25]),
            "Mediana": int(q.loc[0.50]),
            "p75": int(q.loc[0.75]), "p90": int(q.loc[0.90]),
            f"< {UMBRAL_IMPORTS} imports": int((sub["n_imports"] < UMBRAL_IMPORTS).sum()),
        })
    guardar(pd.DataFrame(dist), "T3a_distribucion_imports",
            "Distribucion del numero de importaciones",
            f"El umbral de {UMBRAL_IMPORTS} importaciones separa las muestras en las que "
            "la tabla de importaciones aporta informacion suficiente de aquellas en las "
            "que esta practicamente vacia.")

    # --- Tabla principal: prevalencia segun aplicabilidad ---
    t3 = []
    for etiq_g, sub_g in [("Malware", mal), ("Control", good)]:
        for cond, etiq_c in [(sub_g["n_imports"] < UMBRAL_IMPORTS,
                              f"< {UMBRAL_IMPORTS} imports (no aplicable)"),
                             (sub_g["n_imports"] >= UMBRAL_IMPORTS,
                              f">= {UMBRAL_IMPORTS} imports (aplicable)")]:
            sub = sub_g[cond]
            k, n = int(sub["rtt_any"].sum()), len(sub)
            lo, hi = wilson(k, n)
            t3.append({
                "Grupo": etiq_g,
                "Estrato": etiq_c,
                "Muestras": n,
                "Con RTT": k,
                "Prevalencia %": round(100 * k / n, 1) if n else float("nan"),
                "IC95": f"[{100*lo:.1f}, {100*hi:.1f}]" if n else "",
                "Imports (mediana)": int(sub["n_imports"].median()) if n else 0,
            })
    t3 = pd.DataFrame(t3)

    # --- Lift dentro del estrato aplicable (la comparacion honesta) ---
    ma = mal[mal["n_imports"] >= UMBRAL_IMPORTS]
    ga = good[good["n_imports"] >= UMBRAL_IMPORTS]
    nota = ""
    if len(ma) and len(ga):
        pm, pg = ma["rtt_any"].mean(), ga["rtt_any"].mean()
        if pg > 0:
            nota += f"Lift en el estrato aplicable: {pm/pg:.1f}. "
    try:
        from scipy.stats import fisher_exact
        apl = mal["n_imports"] >= UMBRAL_IMPORTS
        tabla = [[int(((apl) & (mal["rtt_any"] == 1)).sum()),
                  int(((apl) & (mal["rtt_any"] == 0)).sum())],
                 [int((~apl & (mal["rtt_any"] == 1)).sum()),
                  int((~apl & (mal["rtt_any"] == 0)).sum())]]
        odds, pval = fisher_exact(tabla)
        nota += f"Test exacto de Fisher (malware, aplicable vs no aplicable): OR = {odds:.2f}, p = {pval:.3g}."
    except Exception:
        pass
    guardar(t3, "T3_aplicabilidad",
            "Prevalencia de RTT segun aplicabilidad del analisis por importaciones",
            nota + " Las cifras del estrato no aplicable NO son estimaciones de "
                   "prevalencia: son cotas inferiores impuestas por el instrumento. "
                   "Es en ese segmento donde el analisis dinamico con simulacion de "
                   "interaccion constituye la unica via de deteccion.")

    # --- Se conserva la tabla por empaquetado, ahora como secundaria ---
    t3b = []
    for emp, etiq in [(0, "No empaquetada"), (1, "Empaquetada")]:
        sub = mal[mal["empaquetado"] == emp]
        k, n = int(sub["rtt_any"].sum()), len(sub)
        lo, hi = wilson(k, n)
        t3b.append({
            "Grupo": etiq, "Muestras": n, "Con RTT": k,
            "Prevalencia %": round(100 * k / n, 1) if n else float("nan"),
            "IC95": f"[{100*lo:.1f}, {100*hi:.1f}]" if n else "",
            "Imports (mediana)": int(sub["n_imports"].median()) if n else 0,
        })
    guardar(pd.DataFrame(t3b), "T3b_rtt_empaquetado", "RTT frente a empaquetado declarado",
            "Tabla secundaria. La deteccion de empaquetado de capa resulto poco "
            "informativa en este corpus: no marca las muestras que unicamente "
            "ocultan sus importaciones mediante resolucion dinamica.")

    # ---------------------------------------------------------------- T4 ----
    fam = (mal[mal["familia"].notna() & (mal["familia"] != "sin_etiquetar")
               & (mal["n_imports"] >= UMBRAL_IMPORTS)]
           .groupby("familia")
           .agg(Muestras=("sha256", "count"), Con_RTT=("rtt_any", "sum"))
           .reset_index())
    fam = fam[fam["Muestras"] >= 10].copy()          # familias con soporte suficiente
    fam["Prevalencia %"] = (100 * fam["Con_RTT"] / fam["Muestras"]).round(1)
    fam["IC95"] = [f"[{100*a:.1f}, {100*b:.1f}]" for a, b in
                   (wilson(int(k), int(n)) for k, n in zip(fam["Con_RTT"], fam["Muestras"]))]
    fam = fam.sort_values("Muestras", ascending=False).head(TOP_FAMILIAS)
    guardar(fam.rename(columns={"familia": "Familia", "Con_RTT": "Con RTT"}),
            "T4_por_familia", f"Prevalencia por familia (top {TOP_FAMILIAS}, min. 10 muestras)",
            f"Restringida al estrato aplicable (>= {UMBRAL_IMPORTS} importaciones).")

    # ---------------------------------------------------------------- T5 ----
    if mal["first_seen"].notna().any():
        tmp = mal[mal["n_imports"] >= UMBRAL_IMPORTS].copy()
        tmp["anio"] = pd.to_datetime(tmp["first_seen"], errors="coerce").dt.year
        tmp = tmp[tmp["anio"].notna()]
        if len(tmp):
            ev = (tmp.groupby("anio")
                  .agg(Muestras=("sha256", "count"), Con_RTT=("rtt_any", "sum"))
                  .reset_index())
            ev["Prevalencia %"] = (100 * ev["Con_RTT"] / ev["Muestras"]).round(1)
            ev["anio"] = ev["anio"].astype(int)
            guardar(ev.rename(columns={"anio": "Año", "Con_RTT": "Con RTT"}),
                    "T5_evolucion", "Evolucion temporal de la prevalencia",
                    "Interpreta con cautela: refleja cuando se subio la muestra a "
                    "MalwareBazaar, no cuando se creo.")

    # ------------------------------------------------------------ figuras ---
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        etiquetas = [MECANISMOS[c] for c in MECANISMOS]
        pm = [100 * mal[c].mean() for c in MECANISMOS]
        pg = [100 * good[c].mean() for c in MECANISMOS] if len(good) else [0] * len(pm)
        x = np.arange(len(etiquetas)); w = 0.38

        fig, ax = plt.subplots(figsize=(9, 4.5))
        ax.bar(x - w/2, pm, w, label="Malware")
        ax.bar(x + w/2, pg, w, label="Control (goodware)")
        ax.set_ylabel("Prevalencia (%)")
        ax.set_xticks(x); ax.set_xticklabels(etiquetas, rotation=20, ha="right")
        ax.legend(); ax.grid(axis="y", alpha=0.3)
        fig.tight_layout(); fig.savefig(FIGURAS / "fig1_prevalencia.pdf")
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(6, 4))
        grupos = ["No empaquetada", "Empaquetada"]
        vals = [100 * mal[mal.empaquetado == e]["rtt_any"].mean() if len(mal[mal.empaquetado == e]) else 0
                for e in (0, 1)]
        ax.bar(grupos, vals, color=["#4c72b0", "#c44e52"])
        ax.set_ylabel("Muestras con RTT detectado (%)")
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout(); fig.savefig(FIGURAS / "fig2_empaquetado.pdf")
        plt.close(fig)
        print(f"\n  [+] Figuras en {FIGURAS}")
    except ImportError:
        print("\n  [=] matplotlib no instalado: me salto las figuras.")

    print(f"\n[+] Tablas en {TABLAS}")


if __name__ == "__main__":
    main()
