"""
Dashboard para mostrar los datos obtenidos en el experimento del TFG.
Frontend interactivo de los datos de Trivy/Grype/DockerScout
"""

import streamlit as st

st.set_page_config(
    page_title="TFG DevSecOps - COmparativa de escáneres de vulnerabilidades",
    layout="wide",
)

st.title("Comparativa de escáneres de vulnerabilidades en contenedores Docker")
st.caption("Análisis estadístico sobre Trivy, Grype y Docker Scout — TFG, Grado en Informática, URJC")

st.markdown("---")
st.info("Resto en construcción")