"""
Router para los intervalos de confianza bootstrap.

/bootstrap?umbral=N Intervalo de confianza al 95% para el F1 medio de cada escáner, calculado con bootstrap BCa (Efron-Tibshirani 1993, 9999 iteraciones). Disponible para umbrales 2 y 3.
"""

from fastapi import APIRouter, HTTPException, Query
import pandas as pd

from api.config import UMBRAL_DEFAULT, UMBRALES_VALIDOS, bootstrap_csv

router = APIRouter(tags=["bootstrap"])

@router.get("/bootstrap")
def bootstrap(
    umbral: int = Query(
        UMBRAL_DEFAULT,
        description="Umbral de consenso del GT (2=principal, 3=sensibilidad)."
    ),
) -> list[dict]:
    """
    Devuelve el F1 medio y los límites superior e inferior del intervalo de confianza 95% para cada escáner en el umbral elegido.
    """
    if umbral not in UMBRALES_VALIDOS:
        raise HTTPException(
            status_code=422,
            detail=f"Umbral no válido. Valores permitidos: {UMBRALES_VALIDOS}."
        )
    try:
        df = pd.read_csv(bootstrap_csv(umbral))
    except FileNotFoundError:
        raise HTTPException(
            status_code= 503,
            detail=f"bootstrap_ci_umbral{umbral}.csv no encontrado. Por favor, ejecuta analysis/stats.py para generarlo."
        )
    return df.to_dict(orient="records")