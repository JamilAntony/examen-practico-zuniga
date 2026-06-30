#!/usr/bin/env python3
"""
Lab 3 — Tarea 3.4: Script de predicción con modelo entrenado.

Uso:
    python predecir.py nuevo_trafico.csv
"""

import sys
import os
import joblib
import pandas as pd
import numpy as np

MODELO_PATH = "lab3/modelo_anomalias.pkl"
SCALER_PATH = "lab3/scaler.pkl"

FEATURES_NUMERICAS = [
    "dst_port", "bytes_sent", "bytes_recv",
    "duration_sec", "packets",
    "ratio_bytes", "bytes_por_segundo"
]


def cargar_modelo():
    if not os.path.exists(MODELO_PATH):
        print(f"[ERROR] No se encontró el modelo en: {MODELO_PATH}")
        print("  Ejecuta primero el notebook deteccion_anomalias.ipynb")
        sys.exit(1)
    modelo = joblib.load(MODELO_PATH)
    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    return modelo, scaler


def preprocesar(df, scaler=None):
    # Feature engineering (igual que en el notebook)
    df = df.copy()
    df["bytes_recv"] = pd.to_numeric(df["bytes_recv"], errors="coerce").fillna(0)
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0)
    df["duration_sec"] = pd.to_numeric(df["duration_sec"], errors="coerce").fillna(1)
    df["packets"] = pd.to_numeric(df["packets"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)

    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = (df["bytes_sent"] + df["bytes_recv"]) / (df["duration_sec"] + 1)

    X = df[FEATURES_NUMERICAS].copy()

    if scaler is not None:
        X_scaled = scaler.transform(X)
    else:
        X_scaled = X.values

    return X_scaled


def main():
    if len(sys.argv) < 2:
        print("Uso: python predecir.py <archivo_csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"[ERROR] Archivo no encontrado: {csv_path}")
        sys.exit(1)

    print("=" * 65)
    print(" Lab 3 — Predicción de Anomalías en Tráfico de Red")
    print("=" * 65)
    print(f"  Modelo : {MODELO_PATH}")
    print(f"  Archivo: {csv_path}\n")

    # Cargar
    modelo, scaler = cargar_modelo()
    df = pd.read_csv(csv_path)
    print(f"Registros cargados: {len(df)}")

    # Preprocesar y predecir
    X = preprocesar(df, scaler)
    predicciones = modelo.predict(X)          # -1 = anomalía, 1 = normal
    scores = modelo.decision_function(X)      # menor = más anómalo

    df["prediccion"] = predicciones
    df["anomaly_score"] = scores

    # Filtrar anomalías
    anomalias = df[df["prediccion"] == -1].copy()
    anomalias = anomalias.sort_values("anomaly_score")

    print(f"\nAnomalías detectadas: {len(anomalias)} / {len(df)}")
    print(f"Tasa de anomalía: {len(anomalias)/len(df)*100:.1f}%")

    if len(anomalias) == 0:
        print("\nNo se detectaron anomalías en el archivo.")
        return

    print("\n" + "=" * 65)
    print(" REGISTROS CLASIFICADOS COMO ANOMALÍA")
    print("=" * 65)

    cols_mostrar = ["timestamp", "src_ip", "dst_ip", "dst_port",
                    "protocol", "bytes_sent", "bytes_recv", "duration_sec",
                    "packets", "anomaly_score"]
    cols_disponibles = [c for c in cols_mostrar if c in anomalias.columns]

    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", 200)
    pd.set_option("display.float_format", "{:.4f}".format)

    print(anomalias[cols_disponibles].to_string(index=False))

    # Guardar CSV de resultados
    out_path = csv_path.replace(".csv", "_anomalias.csv")
    anomalias.to_csv(out_path, index=False)
    print(f"\nResultados guardados en: {out_path}")


if __name__ == "__main__":
    main()
