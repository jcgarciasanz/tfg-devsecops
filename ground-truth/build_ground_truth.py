import csv
import os
import argparse
from collections import defaultdict
from pathlib import Path

# Variables globales
NORMALIZED_CSV = Path(os.getenv("NORMALIZED_CSV", "analysis/output/normalized.csv"))
OUTPUT_DIR = Path(__file__).parent / "output"

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

# Filtra detecciones que cumplen umbral. Devuelve filas listas para volcar en el csv de ground truth
def filtrar_por_consenso(detecciones: dict, umbral: int) -> list[dict]:
    filas_ground_truth = []

    for(image, cve_id, package), scanners in detecciones.items():
        if len(scanners) >= umbral:
            filas_ground_truth.append({
                "image": image,
                "cve_id": cve_id,
                "package": package,
                "n_scanners": len(scanners),
                # Interesante guardar qué escáneres la detectaron, ordenados para que sea un csv mantenible
                "scanners": ",".join(sorted(scanners)),
            })
    return filas_ground_truth

# FUnción que ejecuta elproceso de agrupar, filtrar y volcar al CSV
def run(csv_path: Path, output_path: Path, umbral: int) -> None:
    print(f"Leyendo detecciones desde {csv_path}...")
    detecciones = agrupar_detecciones(csv_path)
    print(f" -> {len(detecciones)} vulnerabilidades únicas")
    filas = filtrar_por_consenso(detecciones, umbral)
    print(f" -> {len(filas)} pasan el umbral del consenso ({umbral} escáneres mínimos)")

    # Enriquecer CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columnas = ["image", "cve_id", "package", "n_scanners", "scanners"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columnas)
        writer.writeheader()
        writer.writerows(filas)

    print(f"\nGround truth generado en {output_path}")

if __name__ == "__main__":
    # Implementación que deje elegir entre las opciones esperadas pero no romper el flujo previsto
    parser = argparse.ArgumentParser(description="Genera gound truth por consenso multi-tool.")
    parser.add_argument(
        "--umbrales",type=int,nargs="+",choices=[1,2,3],default=[2,3],
        help="Lista de umbrales a generar soportados (default: 2 3)"
    )
    args = parser.parse_args()

    for umbral in args.umbrales:
        # El ground truth principal del TFG mantiene su formato, los demás llevan el sufijo
        sufijo = "" if umbral == 2 else f"_umbral{umbral}"
        run(
            csv_path=NORMALIZED_CSV,
            output_path=OUTPUT_DIR / f"ground_truth{sufijo}.csv",
            umbral=umbral
        )
