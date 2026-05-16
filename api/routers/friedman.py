"""
Router para el test Friedman.

/friedman?umbral=N Test no paramétrico de Friedman sobre F1 por imagen. Disponibles umbrales 2 y 3.
"""

from fastapi import APIRouter, HTTPException, Query
import pandas as pd

from api.config import UMBRAL_DEFAULT, UMBRALES_VALIDOS, friedman_csv

router = APIRouter(tags=["friedman"])


@router.get("/friedman")
def friedman(
    umbral: int = Query(
        UMBRAL_DEFAULT,
        description="Umbral de consenso del GT (2=principal, 3=sensibilidad).",
    ),
)-> dict:
    """
    Devuelve el estadístico Chi-cuadrado, el p-valor y la indicación de significación del test de Friedman para el umbral solicitado.
    """
    if umbral not in UMBRALES_VALIDOS:
        raise HTTPException(
            status_code=422,
            detail=f"Umbral no válido. Valores permitidos: {UMBRALES_VALIDOS}",
        )
    try:
        df = pd.read_csv(friedman_csv(umbral))
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail=f"friedman_umbral{umbral}.csv no encontrado. Por favor, ejecuta analysis/stats.py para generarlo."
        )

    return df.iloc[0].to_dict()
