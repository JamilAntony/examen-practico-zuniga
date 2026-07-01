#!/usr/bin/env python3
import json, os, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from datetime import datetime

REPORTE_SSH = "lab1/reporte_ssh.json"
REPORTE_WEB = "lab1/reporte_web.json"
TRAFICO_CSV = "lab3/network_traffic.csv"
OUT_DIR     = "lab4/evidencias"
os.makedirs(OUT_DIR, exist_ok=True)
sns.set_theme(style="darkgrid")

with open(REPORTE_SSH) as f: ssh = json.load(f)
with open(REPORTE_WEB) as f: web = json.load(f)
df = pd.read_csv(TRAFICO_CSV, parse_dates=["timestamp"])

# Dashboard integrado 4 en 1
fig = plt.figure(figsize=(18, 12))
fig.suptitle("SOC - Monitor de Seguridad\nAlumno: Jamil Zuniga  |  Seguridad Informática  |  " + datetime.now().strftime("%Y-%m-%d %H:%M"), fontsize=14, fontweight="bold")
gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.4, wspace=0.3)

# V1 severidad
ax1 = fig.add_subplot(gs[0,0])
niveles = {"Bajo":0,"Medio":0,"Alto":0,"Crítico":0}
for ip in ssh["ips_sospechosas"]:
    n = ip["intentos"]
    if n<10: niveles["Bajo"]+=1
    elif n<30: niveles["Medio"]+=1
    elif n<100: niveles["Alto"]+=1
    else: niveles["Crítico"]+=1
ax1.bar(niveles.keys(), niveles.values(), color=["#2ecc71","#f39c12","#e74c3c","#8e44ad"])
ax1.set_title("V1 — Alertas por Severidad", fontweight="bold")

# V2 top IPs
ax2 = fig.add_subplot(gs[0,1])
top5 = sorted(ssh["ips_sospechosas"], key=lambda x: x["intentos"], reverse=True)[:5]
ax2.barh([e["ip"] for e in top5][::-1], [e["intentos"] for e in top5][::-1], color="#e74c3c")
ax2.set_title("V2 — Top 5 IPs Atacantes", fontweight="bold")

# V3 timeline
ax3 = fig.add_subplot(gs[1,0])
df["hora"] = df["timestamp"].dt.floor("H")
ph = df.groupby("hora").size()
ax3.plot(range(len(ph)), ph.values, color="#2ecc71", linewidth=2)
ax3.set_title("V3 — Tráfico por Hora", fontweight="bold")

# V4 pie
ax4 = fig.add_subplot(gs[1,1])
grupos = {}
for ip in web["errores_4xx_5xx_por_ip"]:
    for d in ip["detalle"]:
        s = str(d["status"]); grupos[s] = grupos.get(s,0)+1
ax4.pie(grupos.values(), labels=grupos.keys(), autopct="%1.0f%%", colors=["#e74c3c","#3498db","#2ecc71","#f39c12","#9b59b6"])
ax4.set_title("V4 — Distribución por Tipo", fontweight="bold")

fig.savefig(f"{OUT_DIR}/SCR-4.3_dashboard.png", dpi=150, bbox_inches="tight")
plt.close()
print("Dashboard guardado")

# JSON
dashboard = {"title":"SOC - Monitor de Seguridad","author":"Jamil Zuniga","panels":["V1 Severidad","V2 Top IPs","V3 Timeline","V4 Pie"],"time_range":"24h","alert_rule":{"condition":"count > 5","interval":"5min"}}
with open("lab4/dashboard_soc.json","w") as f: json.dump(dashboard, f, indent=2)
print("JSON exportado")
