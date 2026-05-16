""" 
Main para la API Rest del TFG
Levanta FastAPI, registra routers de dominio funcional y configura CORS para Streamlit.
    Lógica -> routers
    Constantes -> config.py
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from api.routers import utilidad, concordancia, friedman

from api.config import API_VERSION

# Metadata para Swagger
# tags_metadata define el orden y descripción de las secciones que muestra Swagger en docs.
tags_metadata=[
    {"name": "metricas","description":"Métricas Precision/Recall/F1 por escáner e imagen y ranking de F1 medio."},
    {"name": "concordancia","description":"Cohen kappa por pares y Fleiss kappa para múltiples evaluadores."},
    {"name": "bootstrap","description":"Intervalos de confianza al 95% para F1 (método BCa)."},
    {"name": "friedman","description":"Test no paramétrico de Friedman sobre F1 por cada imagen."},
    {"name": "datos","description":"Acceso a las vulnerabilidades, ground truth y corpus de imágenes."},
    {"name": "utilidad","description":"Endpoints transversales: health y análisis de sensibilidad obtenida."},
]

app = FastAPI(
    title="TFG DevSecOps, API de análisis comparativo",
    description=(
        "API REST con los resultados del análisis comparativo de Trivy, Grype y "
        "Docker Scout sobre 6 imágenes Docker. Expone las cinco capas del "
        "experimento (P/R/F1, Cohen, Fleiss, Friedman y Bootstrap) para los dos "
        "umbrales de consenso evaluados (2 y 3)."
    ),
    version= API_VERSION,
    openapi_tags=tags_metadata,
)


# CORS
# El dashboard está en :8501, la API en 8000. Sin CORS, el navegador bloquea llamada cross-origin. Para este caso basta con permitir orígenes en localhost, pero en producción se restringiría

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Endpoint de root para redirigir al Swagger
@app.get("/", include_in_schema=False)
def root():
    """Redirección a la raíz de la documentación interactiva."""
    return RedirectResponse(url="/docs")

# REGISTRO DE ROUTERS
app.include_router(utilidad.router)
app.include_router(concordancia.router)
app.include_router(friedman.router)


# REGISTRO DE ROUTERS
# Para hacer seguimiento e ir completando mientras se implementan.