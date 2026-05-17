from fastapi import APIRouter, HTTPException, Query
import pandas as pd

from api.config import(
    NORMALIZED_CSV,
    ground_truth_csv,
    get_imagenes_corpus,
    UMBRALES_VALIDOS,
    UMBRAL_DEFAULT,
    SCANNERS_VALIDOS,
    
)