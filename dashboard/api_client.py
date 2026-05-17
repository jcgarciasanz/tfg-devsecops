"""
Cliente HTTP del dashboard hacia la API REST. Cada función envuelve una llamada a un endpoint de la API y devuelve el JSON parseado, con caché de Streamlit para evitar peticiones redundantes al cambiar de umbral.
"""


import requests
import streamlit as st

from config import API_BASE_URL

def _get(endpoint: str, params: dict | None = None) -> dict | list:
    """

    """
    url = f"{API_BASE_URL}{endpoint}"
    try:
        response=  requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        st.error(f"No se pudo conectar con la API en {API_BASE_URL}. Asegúrate del estado de esta, revisa los logs.")
        st.stop()
    except requests.exceptions.HTTPError as e:
        assert e.response is not None
        st.error(f"Error de la API en {endpoint}: {e.response.status_code} - {e.response.text}")
        st.stop()
    except requests.exceptions.RequestException as e:
        st.error(f"Error inesperado consultando endpoint {endpoint}: {e}")
        st.stop()


# Endpoints análisis
@st.cache_data
def get_metricas(umbral: int) -> dict | list:
    """GET /metricas?umbral=N — P/R/F1 por scanner × imagen."""
    return _get("/metricas",{"umbral": umbral})

@st.cache_data
def get_ranking(umbral: int) -> dict | list:
    """GET /metricas/ranking?umbral=N — F1 medio por scanner, ordenado."""
    return _get("/metricas/ranking", {"umbral": umbral})

@st.cache_data
def get_friedman(umbral: int) -> dict | list:
    """GET /friedman?umbral=N — chi-cuadrado y p-valor."""
    return _get("/friedman", {"umbral": umbral})

@st.cache_data
def get_bootstrap(umbral: int) -> dict|list:
    """GET /bootstrap?umbral=N — F1 medio e IC 95% por scanner."""
    return _get("/bootstrap", {"umbral": umbral})

@st.cache_data
def get_cohen() -> dict|list:
    """GET /concordancia/cohen — kappa por pares de scanners."""
    return _get("/concordancia/cohen")

