# Evaluación Práctica Final — Seguridad Informática
### Unidad IV: Monitoreo de Seguridad, SIEM e Inteligencia Artificial

| Campo | Detalle |
|---|---|
| **Alumno** | Jamil Antony Zuñiga Apaza |
| **Repositorio** | https://github.com/JamilAntony/examen-practico-zuniga |
| **Fecha** | 01 de julio de 2026 |
| **Curso** | Seguridad Informática — Ciclo IX |
| **Entorno** | Ubuntu Server 22.04 LTS en VirtualBox |

## Entorno
- Python 3.10 + venv (pandas, matplotlib, seaborn, scikit-learn, joblib, jupyter)
- Wazuh 4.9.2 All-in-One
- xmllint (libxml2-utils)

## Lab 1 — Análisis Forense de Logs
- 253 intentos fallidos SSH detectados
- 2 IPs con alerta de fuerza bruta: 45.33.32.156 (120) y 193.32.162.55 (58)
- 4 intentos de SQL Injection detectados desde 193.32.162.55
- 3 gráficas generadas (top10 SSH, timeline HTTP, heatmap HTTP)

## Lab 2 — Reglas Wazuh
- Regla 100001: brute force SSH (10 intentos en 60s, nivel 10)
- Regla 100011: exfiltración de datos (login nocturno + >500MB, nivel 14 CRÍTICO)
- MITRE ATT&CK: T1048

## Lab 3 — Detección de Anomalías ML
- Isolation Forest: contamination=0.05, n_estimators=100
- Features: ratio_bytes, bytes_por_segundo + 5 features originales
- Modelo exportado: modelo_anomalias.pkl
- Script de predicción: predecir.py

## Lab 4 — Dashboard SOC
- 4 visualizaciones: severidad, top IPs, timeline, pie de tipos
- Herramienta: Python/Matplotlib (sin instalación adicional)
- Export: dashboard_soc.json
- Regla de alerta: count > 5 eventos en 5 minutos, level >= 10
