import csv
import os
from collections import defaultdict
from pathlib import Path

# Variables globales
NORMALIZED_CSV = Path(os.getenv("NORMALIZED_CSV", "analysis/output/normalized.csv"))
OUTPUT_DIR = Path(__file__).parent / "output"

# UMBRAL CONSENSO:  una vulnerabilidad satisface el ground truth si la detectan al menos n escáneres
UMBRAL_CONSENSO = 2 
# Hay que leer el csv normalizado que se ha generado y agrupar los datos formateados. Devolver un diccionario con la clave en una tupla con los escáneres que lo detectaron.

def agrupar_detecciones(csv_path: Path) -> dict:
    detecciones = defaultdict(set)
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for fila in reader:
            # La clave lógica de una vulnerabilidad única es la combinación de la imagen con el CVE y el paquete
            # Si 2 scans detectan la misma en la misma imagen, quiero tenerlo en cuenta
            clave = (fila["image"], fila["cve_id"], fila["package"])
            detecciones[clave].add(fila["scanner"])

    return detecciones