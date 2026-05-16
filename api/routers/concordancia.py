"""
Router para los endpoints de concordancia entre escáneres.

/concordancia/cohen   Cohen kappa por pares (3 pares de escáneres).
/concordancia/fleiss  Fleiss kappa global (los 3 escáneres a la vez).

Ambas métricas son independientes del umbral del ground truth: se calculan sobre la unión de detecciones, no sobre el GT.
"""

from fastapi import APIRouter, HTTPException
import pandas as pd

from api.config import COHEN_CSV, FLEISS_CSV

router = APIRouter(prefix="/concordancia",tags=["concordancia"])

@router.get("/cohen")
def cohen() -> list[dict]:
    """Cohen's kappa para cada par de escáneres (3 pares en total)."""
    try:
        df = pd.read_csv(COHEN_CSV)
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="cohen_kappa.csv no encontrado. Por favor, ejecuta analysis/stats.py para generarlo."
        )
    return df.to_dict(orient="records")

@router.get("/fleiss")
def fleiss() -> dict:
    """Fleiss kappa sobre los 3 escáneres como evaluadores."""
    try:
        df= pd.read_csv(FLEISS_CSV)
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="fleiss_kappa.csv no encontrado. Por favor, ejecuta analysis/stats.py para generarlo."
        )
    return df.iloc[0].to_dict()