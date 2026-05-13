import json
import os
import csv
from pathlib import Path

# Variables globales
RESULTS_DIR = Path(os.getenv("RESULTS_DIR","/var/jenkins_home/workspace/tfg-devsecops-pipeline/results"))
OUTPUT_DIR = Path(__file__).parent



# Normalización Trivy — JSON propio con Results > Vulnerabilities
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


# Normalización Grype — JSON propio con matches > vulnerability + artifact
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

# Normalización Docker Scout — usa formato SARIF, distinto a Trivy y Grype
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