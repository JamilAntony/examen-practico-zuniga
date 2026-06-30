#!/usr/bin/env python3
"""
Lab 1 — Tarea 1.2
Análisis forense de access.log: detección de escaneo, SQLi y errores HTTP.
"""

import re
import json
from datetime import datetime
from collections import defaultdict

LOG_FILE = "lab1/access.log"
OUTPUT_FILE = "lab1/reporte_web.json"

# Patrones Combined Log Format de Apache
PATRON_CLF = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

# Patrones SQLi
PATRON_SQLI = re.compile(
    r"(UNION|SELECT|--|OR\s+1=1|')", re.IGNORECASE
)

# Umbral escaneo
UMBRAL_RUTAS = 20
VENTANA_SEG = 60


def parsear_tiempo(raw):
    """Convierte '14/Jun/2024:03:13:44 +0000' a timestamp Unix."""
    try:
        return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def detectar_escaneo(registros):
    """Detecta IPs con >20 rutas distintas en <60s."""
    # {ip: [(datetime, path), ...]}
    eventos = defaultdict(list)
    for r in registros:
        eventos[r["ip"]].append((r["tiempo"], r["path"]))

    escaneadores = []
    for ip, items in eventos.items():
        items.sort(key=lambda x: x[0])
        for i in range(len(items)):
            ventana = [p for t, p in items if
                       0 <= (t - items[i][0]).total_seconds() < VENTANA_SEG]
            if len(set(ventana)) > UMBRAL_RUTAS:
                escaneadores.append({
                    "ip": ip,
                    "rutas_distintas": len(set(ventana)),
                    "ventana_segundos": VENTANA_SEG
                })
                break  # evitar duplicados por IP

    return escaneadores


def main():
    print("=" * 60)
    print(" Lab 1 — Análisis Web: access.log")
    print("=" * 60)

    registros = []
    errores_por_ip = defaultdict(list)
    sqli_detectados = []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for linea in f:
            m = PATRON_CLF.match(linea.strip())
            if not m:
                continue
            ip = m.group("ip")
            tiempo = parsear_tiempo(m.group("time"))
            path = m.group("path")
            status = int(m.group("status"))

            if tiempo is None:
                continue

            registros.append({"ip": ip, "tiempo": tiempo, "path": path, "status": status})

            # Códigos 4xx y 5xx
            if status >= 400:
                errores_por_ip[ip].append({"path": path, "status": status})

            # SQLi en URL
            if PATRON_SQLI.search(path):
                sqli_detectados.append({"ip": ip, "path": path, "status": status})

    # Escaneo de directorios
    escaneadores = detectar_escaneo(registros)

    # Consola
    print(f"\nTotal registros parseados: {len(registros)}")

    print(f"\n[ESCANEO DE DIRECTORIOS] {len(escaneadores)} IP(s) detectadas:")
    for e in escaneadores:
        print(f"  IP {e['ip']} → {e['rutas_distintas']} rutas distintas en {e['ventana_segundos']}s")

    print(f"\n[SQLi DETECTADO] {len(sqli_detectados)} petición(es):")
    for s in sqli_detectados[:10]:
        print(f"  IP {s['ip']} → {s['path']}")

    print(f"\n[ERRORES 4xx/5xx] {len(errores_por_ip)} IPs con errores:")
    for ip, errs in sorted(errores_por_ip.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"  {ip}: {len(errs)} errores")

    # Exportar JSON
    resultado = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_registros": len(registros),
        "escaneo_directorios": escaneadores,
        "sqli_detectado": sqli_detectados,
        "errores_4xx_5xx_por_ip": [
            {"ip": ip, "cantidad_errores": len(errs), "detalle": errs[:5]}
            for ip, errs in sorted(errores_por_ip.items(), key=lambda x: -len(x[1]))
        ]
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado → {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
