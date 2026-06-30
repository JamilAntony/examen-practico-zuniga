#!/usr/bin/env python3
"""
Lab 1 — Tarea 1.3
Generación de gráficas desde los reportes JSON y logs.
Requiere: matplotlib, seaborn, pandas
"""

import re
import json
import os
from collections import defaultdict
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # modo sin pantalla
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd

# ── Rutas ──────────────────────────────────────────────────────────────────
JSON_SSH   = "lab1/reporte_ssh.json"
LOG_WEB    = "lab1/access.log"
DIR_GRAFICAS = "lab1/graficas"

os.makedirs(DIR_GRAFICAS, exist_ok=True)

PATRON_CLF = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

sns.set_theme(style="darkgrid")


# ── Gráfica 1: Top 10 IPs SSH ──────────────────────────────────────────────
def grafica_top10_ssh():
    with open(JSON_SSH, "r") as f:
        data = json.load(f)

    top10 = sorted(data["ips_sospechosas"], key=lambda x: x["intentos"], reverse=True)[:10]
    ips = [e["ip"] for e in top10]
    intentos = [e["intentos"] for e in top10]
    colores = ["#e74c3c" if e["alerta"] else "#3498db" for e in top10]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(ips[::-1], intentos[::-1], color=colores[::-1], edgecolor="white")
    ax.set_xlabel("Número de intentos fallidos", fontsize=12)
    ax.set_ylabel("Dirección IP", fontsize=12)
    ax.set_title("Top 10 IPs con más intentos fallidos SSH", fontsize=14, fontweight="bold")

    for bar, val in zip(bars, intentos[::-1]):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=10)

    from matplotlib.patches import Patch
    leyenda = [Patch(color="#e74c3c", label="Alerta (≥50)"),
               Patch(color="#3498db", label="Normal")]
    ax.legend(handles=leyenda, loc="lower right")

    plt.tight_layout()
    ruta = f"{DIR_GRAFICAS}/top10_ssh.png"
    fig.savefig(ruta, dpi=150)
    plt.close()
    print(f"  [OK] Guardada: {ruta}")


# ── Gráfica 2: Peticiones HTTP por hora ────────────────────────────────────
def grafica_timeline_http():
    por_hora = defaultdict(int)

    with open(LOG_WEB, "r") as f:
        for linea in f:
            m = PATRON_CLF.match(linea.strip())
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group("time").split()[0], "%d/%b/%Y:%H:%M:%S")
                hora = dt.replace(minute=0, second=0, microsecond=0)
                por_hora[hora] += 1
            except ValueError:
                continue

    horas = sorted(por_hora.keys())
    conteos = [por_hora[h] for h in horas]

    fig, ax = plt.subplots(figsize=(14, 5))
    ax.plot(horas, conteos, marker="o", linewidth=2, color="#2ecc71", markersize=5)
    ax.fill_between(horas, conteos, alpha=0.25, color="#2ecc71")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
    plt.xticks(rotation=45, ha="right")
    ax.set_xlabel("Hora del día", fontsize=12)
    ax.set_ylabel("Número de peticiones", fontsize=12)
    ax.set_title("Peticiones HTTP por hora", fontsize=14, fontweight="bold")
    plt.tight_layout()

    ruta = f"{DIR_GRAFICAS}/timeline_http.png"
    fig.savefig(ruta, dpi=150)
    plt.close()
    print(f"  [OK] Guardada: {ruta}")


# ── Gráfica 3: Heatmap peticiones por hora y código HTTP ──────────────────
def grafica_heatmap_http():
    codigos_interes = [200, 301, 302, 304, 404, 500]
    matriz = defaultdict(lambda: defaultdict(int))  # {hora: {codigo: count}}

    with open(LOG_WEB, "r") as f:
        for linea in f:
            m = PATRON_CLF.match(linea.strip())
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group("time").split()[0], "%d/%b/%Y:%H:%M:%S")
                hora = dt.hour
                status = int(m.group("status"))
                if status in codigos_interes:
                    matriz[hora][status] += 1
            except ValueError:
                continue

    # Construir DataFrame
    horas = list(range(24))
    df = pd.DataFrame(
        [[matriz[h].get(c, 0) for c in codigos_interes] for h in horas],
        index=[f"{h:02d}:00" for h in horas],
        columns=[str(c) for c in codigos_interes]
    )

    fig, ax = plt.subplots(figsize=(12, 8))
    sns.heatmap(df, annot=True, fmt="d", cmap="YlOrRd", linewidths=0.5,
                ax=ax, cbar_kws={"label": "Número de peticiones"})
    ax.set_title("Peticiones HTTP por hora y código de respuesta", fontsize=14, fontweight="bold")
    ax.set_xlabel("Código HTTP", fontsize=12)
    ax.set_ylabel("Hora del día", fontsize=12)
    plt.tight_layout()

    ruta = f"{DIR_GRAFICAS}/heatmap_http.png"
    fig.savefig(ruta, dpi=150)
    plt.close()
    print(f"  [OK] Guardada: {ruta}")


# ── Main ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print(" Lab 1 — Generando visualizaciones")
    print("=" * 60)
    print("\n[1] Top 10 IPs SSH...")
    grafica_top10_ssh()
    print("[2] Línea de tiempo HTTP...")
    grafica_timeline_http()
    print("[3] Heatmap HTTP...")
    grafica_heatmap_http()
    print("\nTodas las gráficas guardadas en:", DIR_GRAFICAS)
