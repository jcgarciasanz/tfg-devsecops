"""
Configuración del dashboard. URL de la API, paleta por escáner y definción de constantes compartidas.
"""
API_BASE_URL="http://localhost:8000"

SCANNER_COLORS={
    "trivy": "#1f3a5f",
    "grype": "#5a7d2e",
    "dockerscout": "#7d5a2e",
}

UMBRALES_DISPONIBLES = [2,3]
UMBRAL_DEFAULT = 2