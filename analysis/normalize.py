import json
import os
import csv
from pathlib import Path

#Variables globales
RESULTS_DIR = Path(os.getenv("RESULTS_DIR","/var/jenkins_home/workspace/tfg-devsecops-pipeline/results"))
OUTPUT_DIR = Path(__file__).parent



#Nornmalización salida archivos resultado Trivy
def normalize_trivy(filepath: Path, image: str) -> list[dict]:
    with open(filepath) as f:
        data = json.load(f)
    
    rows = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            rows.append({
                "scanner": "trivy",
                "image": image,
                "cve_id": vuln.get("VulnerabilityID",""),
                "package": vuln.get("PkgName",""),
                "version": vuln.get("InstalledVersion",""),
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
            })
    return rows

#Nornmalización salida archivos resultado Grype
def normalize_grype(filepath: Path, image: str) -> list[dict]:
    with open(filepath) as f:
        data = json.load(f)

    rows = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        rows.append({
            "scanner": "grype",
            "image": image,
            "cve_id": vuln.get("id",""),
            "package": artifact.get("name",""),
            "version": artifact.get("version",""),
            "severity": vuln.get("severity", "UNKNOWN").upper(),
        })
    return rows