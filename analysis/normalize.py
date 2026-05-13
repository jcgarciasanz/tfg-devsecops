import json
import os
import csv
from pathlib import Path

# Lista de imágenes, mismo orden que Jenkinsfile
CORPUS = [
    "python-3.9-slim-bookworm",
    "python-3.9-alpine3.18",
    "node-16-slim",
    "node-16-alpine3.18",
    "nginx-1.20",
    "debian-bullseye-slim",
]

# Variables globales
RESULTS_DIR = Path(os.getenv("RESULTS_DIR","/var/jenkins_home/workspace/tfg-devsecops-pipeline/results"))
OUTPUT_DIR = Path(__file__).parent / "output"



# Normalización Trivy, JSON propio con Results > Vulnerabilities
def normalize_trivy(filepath: Path, image: str) -> list[dict]:
    with open(filepath) as f:
        data = json.load(f)

    rows = []
    for result in data.get("Results", []):
        # Vulnerabilities puede ser None si la capa no tiene vulns, por eso el "or []"
        for vuln in result.get("Vulnerabilities") or []:
            rows.append({
                "scanner": "trivy",
                "image": image,
                "cve_id": vuln.get("VulnerabilityID", ""),
                "package": vuln.get("PkgName", ""),
                "version": vuln.get("InstalledVersion", ""),
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
            })
    return rows


# Normalización Grype, JSON propio con matches > vulnerability + artifact
def normalize_grype(filepath: Path, image: str) -> list[dict]:
    with open(filepath) as f:
        data = json.load(f)

    rows = []
    for match in data.get("matches", []):
        # Grype separa los datos de la vuln y del paquete en dos objetos distintos
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        rows.append({
            "scanner": "grype",
            "image": image,
            "cve_id": vuln.get("id", ""),
            "package": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            # Grype usa primera letra mayúscula, .upper() lo normaliza igual que Trivy
            "severity": vuln.get("severity", "UNKNOWN").upper(),
        })
    return rows

# Normalización Docker Scout, usa formato SARIF, distinto a Trivy y Grype
def normalize_docker_scout(filepath: Path, image: str) -> list[dict]:
    with open(filepath) as f:
        data = json.load(f)

    rows = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            cve_id = result.get("ruleId", "")

            # Scout no estructura los datos en campos JSON como Trivy o Grype.
            # Los mete en un string de texto en message.text, hay que parsearlo a mano.
            msg = result.get("message", {}).get("text", "")
            severity = "UNKNOWN"
            package = ""
            version = ""

            for line in msg.splitlines():
                line = line.strip()
                if line.startswith("Severity"):
                    severity = line.split(":")[-1].strip()
                elif line.startswith("Package"):
                    # El paquete viene en PURL, ej: pkg:pypi/pip@23.0.1
                    # maxsplit=1 porque el valor puede tener ":" dentro
                    purl = line.split(":", 1)[-1].strip()
                    if "@" in purl:
                        partes_purl = purl.split("@")
                        version = partes_purl[-1].strip()
                        package = partes_purl[0].split("/")[-1].strip()

            rows.append({
                "scanner": "scout",
                "image": image,
                "cve_id": cve_id,
                "package": package,
                "version": version,
                "severity": severity.upper(),
            })
    return rows

#Función para ejecutar los normalize
def run(results_dir: Path, output_path: Path) -> None:
    todas_las_filas = []
    # Espacio después de almohadilla, sino saltan estilos y no encuentras error
    # Por cada imagen del Corpus, lanzo los 3
    # Si la ruta no existe, no aborto el script entero — sigo con los demás.
    # Así un fallo puntual de un escáner no me tira toda la ejecución.

    for imagen in CORPUS:
        # TRIVY
        ruta_trivy = results_dir / f"trivy_{imagen}.json"
        if ruta_trivy.exists(): # Importante
            filas = normalize_trivy(ruta_trivy, imagen)
            todas_las_filas.extend(filas)
            print(f"trivy / {imagen}: {len(filas)} vulns")
        else:
            print(f"ERROR: no encontrada ruta de Trivy {ruta_trivy}")
        
        # GRYPE
        ruta_grype = results_dir / f"grype_{imagen}.json"
        if ruta_grype.exists():
            filas = normalize_grype(ruta_grype, imagen)
            todas_las_filas.extend(filas)
            print(f"grype / {imagen}: {len(filas)} vulns")
        else:
            print(f"ERROR: no encontrada ruta Grype {ruta_grype}")
        
        # DOCKER SCOUT
        ruta_scout = results_dir / f"scout_{imagen}.json"
        if ruta_scout.exists():
            filas = normalize_docker_scout(ruta_scout, imagen)
            todas_las_filas.extend(filas)
            print(f"scout / {imagen}: {len(filas)} vulns")
        else:
            print(f"ERROR: no encontrada ruta de Docker Scout {ruta_scout}")

    # Ahora hay que pasar todo al CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columnas = ["scanner", "image", "cve_id", "package", "version", "severity"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columnas)
        writer.writeheader()
        writer.writerows(todas_las_filas)
    print(f"\nTotal: {len(todas_las_filas)} filas -> {output_path}")

if __name__ == "__main__":
    # Necesario para discriminar entre si se ejecuta en Jenkins o en local para testear al desarrollar. En Jenkins BUILD_NUMBER viene, en local lo pongo yo
    build = os.getenv("BUILD_NUMBER", "latest")
    run(
        results_dir= RESULTS_DIR / build,
        output_path= OUTPUT_DIR / "normalized.csv"
    )
