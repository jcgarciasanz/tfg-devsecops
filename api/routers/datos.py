from fastapi import APIRouter, HTTPException, Query
import pandas as pd

from api.config import(
    NORMALIZED_CSV,
    ground_truth_csv,
    get_imagenes_corpus,
    get_severities_validas,
    UMBRALES_VALIDOS,
    UMBRAL_DEFAULT,
    SCANNERS_VALIDOS,
)

router = APIRouter(tags=["datos"])

def _carga_normalized() -> pd.DataFrame:
    """Carga de csv normalizado. Si no existe lanza un 503."""
    try:
        return pd.read_csv(NORMALIZED_CSV)
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="normalized.csv no encontrado. Por favor, ejecuta analysis/stats.py para generarlo."
        )
    
@router.get("/vulnerabilidades")
def get_vulnerabilidades(
    scanner: str | None = Query(default=None, description="Filtro por escáner"),
    imagen: str | None = Query(default=None, description="Filtro por imagen del corpus"),
    severity: str | None = Query(default=None, description="Filtro por severidad"),
    limit: int = Query(default=1000, ge=1, le=20000, description="Máximo de filas a devolver"),
):
    """
    Detecciones individuales de normalized.csv con filtros opcionales (scanner, imagen, severity). Paginado con limit para no devolver los ~12k registros del CSV de golpe. `total` cuenta lo filtrado antes del limit.
    """
    # Validación de filtros vs listas canónicas
    if scanner is not None and scanner not in SCANNERS_VALIDOS:
        raise HTTPException(
            status_code=422,
            detail=f"Escáner no válido. Los escáneres válidos son: {sorted(SCANNERS_VALIDOS)}",
        )
    if imagen is not None and imagen not in get_imagenes_corpus():
        raise HTTPException(
            status_code=422,
            detail=f"Imagen no disponible en corpus. Imágenes disponibles: {get_imagenes_corpus()}",
        )
    if severity is not None and severity not in get_severities_validas():
        raise HTTPException(
            status_code=422,
            detail=f"Severity no válida. Severities válidas: {sorted(get_severities_validas())}",
        )
    
    df = _carga_normalized()

    if scanner is not None:
        df = df[df["scanner"] == scanner]
    if imagen is not None:
        df = df[df["image"] == imagen]
    if severity is not None:
        df = df[df["severity"] == severity]

    total = len(df)
    df_limited = df.head(limit)

    return {
        "total": total,
        "devueltas": len(df_limited),
        "vulnerabilidades": df_limited.to_dict(orient="records"),
    }

@router.get("/ground-truth")
def get_ground_truth(
    umbral: int=Query(default=UMBRAL_DEFAULT, description="Umbral de consenso del GT (2=principal, 3=sensibilidad)"),
):
    """
    Ground truth por consenso multi-tool. Umbral 2 da consenso parcial (+-1388 vulns), umbral 3 consenso total (+-173 vulns). Sin paginar: el dataset es pequeño y normalmente se quiere entero.
    """
    if umbral not in UMBRALES_VALIDOS:
        raise HTTPException(
            status_code=422,
            detail=f"Umbral no válido. Umbrales válidos: {sorted(UMBRALES_VALIDOS)}",
        )
    try:
        df = pd.read_csv(ground_truth_csv(umbral))
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail=f"GT con umbral {umbral} no encontrado. Por favor, ejecuta ground-truth/build_ground_truth.py",
        )
    return {
        "umbral": umbral,
        "total": len(df),
        "ground_truth": df.to_dict(orient="records"),
    }

@router.get("/imagenes")
def get_imagenes():
    """
    Lista de imágenes del corpus declarado (leído lazy de normalized.csv).
    """
    imagenes = get_imagenes_corpus()
    return {"total": len(imagenes), "imagenes": imagenes}