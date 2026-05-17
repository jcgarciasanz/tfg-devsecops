"""
Dashboard para mostrar los datos obtenidos en el experimento del TFG.
Frontend interactivo de los datos de Trivy/Grype/DockerScout
"""

import streamlit as st
import api_client
from config import UMBRALES_DISPONIBLES, UMBRAL_DEFAULT

st.set_page_config(
    page_title="TFG DevSecOps - Comparativa de escáneres de vulnerabilidades",
    layout="wide",
)
# SIDEBAR
st.sidebar.header("Configuración")
umbral = st.sidebar.radio(
    "Umbral de consenso del ground truth",
    options=UMBRALES_DISPONIBLES,
    index=UMBRALES_DISPONIBLES.index(UMBRAL_DEFAULT),
    help="Umbral 2: consenso parcial (ground truth amplio). Umbral 3 : consenso total (ground truth estricto)."
)
st.sidebar.markdown("---")

# Estado de la API
st.sidebar.subheader("Estado del sistema")
health= api_client.get_health()
assert isinstance(health, dict)
st.sidebar.write(f"API: {health['status']}")
st.sidebar.write(f"Versión: {health['api_version']}")
st.sidebar.write(f"Fecha experimento: {health['experiment_date']}")
st.sidebar.markdown("---")

# Corpus de imágenes
st.sidebar.subheader("Corpus de imágenes")
imagenes_data = api_client.get_imagenes()
assert isinstance(imagenes_data, dict)
st.sidebar.write(f"Total: {imagenes_data['total']} imágenes")
for imagen in imagenes_data['imagenes']:
    st.sidebar.write(f"- {imagen}")



# Contenido fijo
st.title("Comparativa de escáneres de vulnerabilidades en contenedores Docker")
st.caption("Análisis estadístico sobre Trivy, Grype y Docker Scout — TFG, Grado en Informática, URJC")

st.markdown("---")
st.write(f"Umbral seleccionado: **{umbral}**")
st.info("Resto en construcción")