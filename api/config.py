#####Configuración para la API Rest###
"""
Fichero para centralizar todas las rutas, constantes y validaciones de tal manera que cualquier cambio o actualización se gestione desde aquí
""" 

from functools import lru_cache
from pathlib import Path
import pandas as pd




# Ruta base
# Sirve para poder localiza los outputs y no definirlo más que 1 sola vez, agilizando cambios
BASE_DIR = Path(__file__).resolve().parent.parent

GROUND_TRUTH_OUTPUT_DIR = BASE_DIR / "ground-truth" / "output"
ANALYSIS_OUTPUT_DIR = BASE_DIR / "analysis" / "output"

# Rutas de los csv generados de estadísiticas para su análisis
NORMALIZED_CSV = ANALYSIS_OUTPUT_DIR / "normalized.csv"
COHEN_CSV = ANALYSIS_OUTPUT_DIR / "cohen_kappa.csv"
FLEISS_CSV = ANALYSIS_OUTPUT_DIR / "fleiss_kappa.csv"

# CSV por umbral
# Funciones para encapsular el tema del naming, de querer cambiarlo, se modifica aquí y afecta a lo demás

def metricas_csv(umbral:int) -> Path:
    return ANALYSIS_OUTPUT_DIR/f"metricas_umbral{umbral}.csv"

def friedman_csv(umbral:int) -> Path:
    return ANALYSIS_OUTPUT_DIR/f"friedman_umbral{umbral}.csv"

def bootstrap_csv(umbral: int) -> Path:
    return ANALYSIS_OUTPUT_DIR / f"bootstrap_ci_umbral{umbral}.csv"

def ground_truth_csv(umbral:int) -> Path:
    # Umbral 2 sin sufijo (GT principal del TFG), umbral 3 con sufijo(sensibilidad)
    if umbral == 2:
        return GROUND_TRUTH_OUTPUT_DIR / "ground_truth.csv"
    return GROUND_TRUTH_OUTPUT_DIR / f"ground_truth_umbral{umbral}.csv"

UMBRALES_VALIDOS = [2,3]
UMBRAL_DEFAULT = 2

SCANNERS_VALIDOS = ["trivy","grype","scout"]

# Corpus imágenes: carga lazy + cache
@lru_cache(maxsize=1)
def get_imagenes_corpus()-> list[str]:
    """
    Devuelve la lista ordenada de las imágenes que conforman el corpus, leída de noramlized.cs
    se calcula en la primera llamada y se cachea para las siguientes. Si no lo encuentra, lanza 503
    """
    df = pd.read_csv(NORMALIZED_CSV)
    return sorted(df["image"].unique().tolist())




# Para /health
API_VERSION = "0.1.0"
EXPERIMENT_DATE = "2026-05-15"