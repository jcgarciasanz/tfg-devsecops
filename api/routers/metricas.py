"""
Router para servir métricas Precission/Recall/F1 por escáner e imagen.

/metricas          Métricas filtrables por umbral, escáner e imagen. Sin filtrar, devuelve las 18 filas: 3 escáneres por las 6 imágenes disponibles en el corpus.

/metricas/ranking  F1 medio por escáner, ordenado de manera descendente. Se calcula agrupando el CSV de métricas, no se lee de bootstrap. Así sirve también como check de consistencia entre CSV's.
"""

from fastapi import APIRouter, HTTPException, Query
import pandas as pd

from api.config import(
    SCANNERS_VALIDOS,
    UMBRAL_DEFAULT,
    UMBRALES_VALIDOS,
    get_imagenes_corpus,
    metricas_csv,
)

router = APIRouter(prefix="/metricas",tags=["metricas"])

def _carga_metricas(umbral:int) -> pd.DataFrame:
    """
    Encargada de la carga del CSV de métricas para el umbral seleccionado. Si no existe, devuelve un 503 con descripción del error.
    """
    try:
        return pd.read_csv(metricas_csv(umbral))
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail=f"metricas_umbral{umbral}.csv no encontrado. Por favor, ejecuta analysis/stats.py para generarlo."
        )
    


@router.get("")
def metricas(
    umbral: int = Query(
        UMBRAL_DEFAULT,
        description="Umbral de consenso del GT (2:principal, 3:sensibilidad)."
    ),
    scanner: str | None = Query(
        None,
        description=f"Filtra por escáner. Valores válidos: {SCANNERS_VALIDOS}."
    ),
    imagen: str | None = Query(       None,
        description = "Filtra por imagen del corpus (/imagenes)."
    ),
) -> list[dict]:
    """
    Devuelve las métricas P/R/F1 por escáner e imagen para el umbral indicado. Los filtros scanner e imagen son opcionales y combinables.
    """
    # Umbral vs lista de config
    if umbral not in UMBRALES_VALIDOS:
        raise HTTPException(
            status_code= 422,
            detail=f"Umbral no válido. Valores permitidos: {UMBRALES_VALIDOS}."
        )
    # Validación de scanner si lo tiene la query
    if scanner is not None and scanner not in SCANNERS_VALIDOS:
        raise HTTPException(
            status_code=422,
            detail=f"Escáner no válido. Valores permitidos: {SCANNERS_VALIDOS}",
        )
    
    # Validación de imagen si lo tiene la query
    if imagen is not None and imagen not in get_imagenes_corpus():
        raise HTTPException(
            status_code=422,
            detail=f"Imagen no válida. Valores permitidos: {get_imagenes_corpus()}",
        )

    df = _carga_metricas(umbral)

    # FIltros que solo se aplican si los tiene la query
    if scanner is not None:
        df = df[df["scanner"] == scanner]
    if imagen is not None:
        df = df[df["image"] == imagen]
    
    return df.to_dict(orient="records")

@router.get("/ranking")
def ranking(
    umbral: int = Query(
        UMBRAL_DEFAULT,
        description="Umbral de consenso del GT (2:principal, 3:sensibilidad).",
    ),
) -> list[dict]:
    """
    F1 medio por escáner para el umbral indicado, ordenado descendente. Calculado agrupando el CSV de métricas. Verifica implícitamente la coherencia con bootstrap_ci_umbral{N}.csv.
    """
    if umbral not in UMBRALES_VALIDOS:
        raise HTTPException(
            status_code= 422,
            detail=f"Umbral no válido. Valores permitidos: {UMBRALES_VALIDOS}.",
        )
    
    df = _carga_metricas(umbral)

    # F1 medio por escáner, redondeado a 4 decimales
    ranking_df = (
        df.groupby("scanner")["f1"]
        .mean()
        .round(4)
        .reset_index()
        .rename(columns={"f1":"f1_mean"})
        .sort_values("f1_mean", ascending=False)
        .reset_index(drop=True)   
    )
    ranking_df["posicion"]=ranking_df.index+1

    return ranking_df.to_dict(orient="records")