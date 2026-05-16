"""
Router de endpoints

Resumen de los implementados:

/health          metadata de la API
/sensibilidad    ranking F1 medio para umbral 2 y 3 en la misma respuesta. Endpoint que muestra el hallazgo clave del TFG: inversión de ranking de escáneres según criterio.

"""

from fastapi import APIRouter, HTTPException
import pandas as pd

from api.config import(
    API_VERSION,
    EXPERIMENT_DATE,
    UMBRALES_VALIDOS,
    bootstrap_csv,
)

router = APIRouter(tags=["utilidad"])

@router.get("/health")
def health() -> dict:
    """
    Este endpoint expone el estado y metadata de la API. Hecho para consulta del servicio y umbrales disponibles para el experimento
    """
    return{
        "status": "ok",
        "api_version": API_VERSION,
        "experiment_date": EXPERIMENT_DATE,
        "umbrales_disponibles": UMBRALES_VALIDOS,
    }

@router.get("/sensibilidad")
def sensibilidad()-> dict:
    """Ranking F1 medio por escáner para umbral 2 y umbral 3. Muestra la inversión del ranking según el criterio de consenso del GT."""
    resultado = {}

    for umbral in UMBRALES_VALIDOS:
        try:
            df=pd.read_csv(bootstrap_csv(umbral))
        except FileNotFoundError:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Datos no disponibles para umbral={umbral}. "
                    f"Ejecutar analysis/stats.py para generar los CSVs necesarios."
                ),
            )
        # Orden descendente por F1 medio y asignación de posición
        df = df.sort_values("f1_mean", ascending=False).reset_index(drop=True)
        df["posicion"]=df.index+1
        ranking=df[["scanner","f1_mean","posicion"]].to_dict(orient="records")

        resultado[f"umbral_{umbral}"]={
            "ranking": ranking,
            "top_scanner": ranking[0]["scanner"],
        }
    
    resultado["hallazgo"]=(
        "El ranking de escáneres se invierte entre umbrales: con umbral 2 (consenso "
        "parcial entre los escáneres) gana Trivy, mientras que con umbral 3 (consenso "
        "total) el ganador pasa a ser Scout. Decir cuál es 'el mejor' escáner depende "
        "por tanto del criterio que se aplique para definir qué es una vulnerabilidad "
        "real. El análisis detallado está en la sección de sensibilidad de la memoria."
    )
    return resultado