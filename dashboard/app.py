"""
Dashboard para mostrar los datos obtenidos en el experimento del TFG.
Frontend interactivo de los datos de Trivy/Grype/DockerScout
"""

import streamlit as st
import plotly.graph_objects as go
import api_client
from config import UMBRALES_DISPONIBLES, UMBRAL_DEFAULT, SCANNER_COLORS

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

# Gráfica F1 con bootstrap
st.subheader(f"F1 medio por escáner (umbral {umbral})")
bootstrap_data=api_client.get_bootstrap(umbral)
assert isinstance(bootstrap_data, list)
bootstrap_data = sorted(bootstrap_data, key=lambda x:x["f1_mean"],reverse=True)

scanner = [item["scanner"] for item in bootstrap_data]
f1_mean = [item["f1_mean"] for item in bootstrap_data]
ci_lows = [item["f1_mean"] - item["f1_ci_low"] for item in bootstrap_data]
ci_highs = [item["f1_ci_high"] - item["f1_mean"] for item in bootstrap_data]
colors = [SCANNER_COLORS[s] for s in scanner]

fig = go.Figure()
fig.add_trace(go.Bar(
    x=[s.capitalize() for s in scanner],
    y=f1_mean,
    error_y=dict(
        type="data",
        symmetric= False,
        array=ci_highs,
        arrayminus=ci_lows,
        color="#888888",
        thickness=1.5,
        width=8
    ),
    marker_color=colors,
    width=0.5
))
fig.update_layout(
    yaxis=dict(title="F1 medio", range=[0, 1.05]),
    xaxis=dict(title="Escáner"),
    showlegend=False,
    height=400,
    margin=dict(l=40,r=40,t=20,b=40),
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
)
st.plotly_chart(fig, use_container_width=True)
st.markdown("---")


st.write(f"Umbral seleccionado: **{umbral}**")
st.info("Resto en construcción")