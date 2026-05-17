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
# Card de hallazgo
st.subheader("Hallazgo principal")

sensibilidad = api_client.get_sensibilidad()
assert isinstance(sensibilidad, dict)

col_u2, col_u3 = st.columns(2)

with col_u2:
    u2 = sensibilidad["umbral_2"]
    top_u2 = u2["top_scanner"]
    f1_top_u2 = u2["ranking"][0]["f1_mean"]
    st.markdown("**Umbral 2** (consenso parcial)")
    st.markdown(f"Top scanner: **{top_u2.capitalize()}**")
    st.markdown(f"F1 medio: {f1_top_u2:.4f}")
with col_u3:
    u3 = sensibilidad["umbral_3"]
    top_u3 = u3["top_scanner"]
    f1_top_u3 = u3["ranking"][0]["f1_mean"]
    st.markdown("**Umbral 3** (consenso total)")
    st.markdown(f"Top scanner: **{top_u3.capitalize()}**")
    st.markdown(f"F1 medio: {f1_top_u3:.4f}")

st.markdown(sensibilidad["hallazgo"])
st.markdown("---")



st.write(f"Umbral seleccionado: **{umbral}**")
st.info("Resto en construcción")