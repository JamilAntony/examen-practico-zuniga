#!/usr/bin/env python3
"""
Lab 1 — Tarea 1.1
Análisis forense de auth.log: detección de fuerza bruta SSH.
"""

import re
import json
from datetime import datetime
from collections import defaultdict

LOG_FILE = "lab1/auth.log"
OUTPUT_FILE = "lab1/reporte_ssh.json"
UMBRAL_ALERTA = 50

def parsear_auth_log(ruta):
    """Lee auth.log y retorna lista de IPs con intentos fallidos."""
    patron = re.compile(r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)")
    conteo = defaultdict(int)

    with open(ruta, "r", encoding="utf-8") as f:
        for linea in f:
            m = patron.search(linea)
            if m:
                ip = m.group(1)
                conteo[ip] += 1

    return conteo

def main():
    print("=" * 60)
    print(" Lab 1 — Análisis SSH: auth.log")
    print("=" * 60)

    conteo = parsear_auth_log(LOG_FILE)

    total = sum(conteo.values())
    print(f"\nTotal intentos fallidos encontrados: {total}")

    # Top 10 IPs
    top10 = sorted(conteo.items(), key=lambda x: x[1], reverse=True)[:10]

    print("\nTop 10 IPs con más intentos fallidos:")
    print(f"{'Rank':<5} {'IP':<20} {'Intentos':<10}")
    print("-" * 40)
    for rank, (ip, n) in enumerate(top10, 1):
        print(f"{rank:<5} {ip:<20} {n:<10}")

    # Alertas
    alertas = []
    print("\nAlertas generadas:")
    for ip, n in conteo.items():
        alerta = n >= UMBRAL_ALERTA
        if alerta:
            msg = f"[ALERTA] IP: {ip} — {n} intentos fallidos — Posible ataque de fuerza bruta"
            print(msg)
        alertas.append({"ip": ip, "intentos": n, "alerta": alerta})

    if not any(a["alerta"] for a in alertas):
        print("  (Ninguna IP superó el umbral de 50 intentos)")

    # Ordenar para el JSON
    alertas_ordenadas = sorted(alertas, key=lambda x: x["intentos"], reverse=True)

    # Exportar JSON
    resultado = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total,
        "ips_sospechosas": alertas_ordenadas
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
