"""
Dashboard para mostrar los datos obtenidos en el experimento del TFG.
Frontend interactivo de los datos de Trivy/Grype/DockerScout
"""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import api_client
from config import UMBRALES_DISPONIBLES, UMBRAL_DEFAULT, SCANNER_COLORS

st.set_page_config(
    page_title="TFG DevSecOps - Comparativa de escáneres de vulnerabilidades",
    layout="wide",
)

st.markdown("""
<style>
[data-testid="stCaptionContainer"] {
    font-size: 1.15rem !important;
}
</style>
""", unsafe_allow_html=True)


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

#Métricas Friedman
st.subheader(f"Test de Friedman (umbral {umbral})")
friedman_data=api_client.get_friedman(umbral)
assert isinstance(friedman_data, dict)
col_chi, col_p, col_sig = st.columns(3)

with col_chi:
    st.metric(
        label="Chi-cuadrado",
        value=f"{friedman_data['statistic']:.4f}",
    )
with col_p:
    st.metric(
        label="p-valor",
        value=f"{friedman_data['pvalue']:.4f}",
    )
with col_sig:
    significativo = friedman_data["significativo"]
    st.metric(
        label="Significativo (α=0.05)",
        value="Sí" if significativo else "No",
    )

st.caption(
    f"Test no paramétrico de Friedman sobre F1 por imagen "
    f"({friedman_data['num_imagenes']} imágenes-bloques, 3 escáneres-tratamientos). "
    f"H₀: no hay diferencias entre escáneres. "
    f"{'Rechazada' if significativo else 'No rechazada'} con p < 0.05."
)
st.markdown("---")

# Tabla scanner x imagen

st.subheader(f"Métricas por escáner e imagen (umbral {umbral})")
metricas_data = api_client.get_metricas(umbral)
assert isinstance(metricas_data, list)

df_metricas = pd.DataFrame(metricas_data)
df_metricas = df_metricas[["scanner","image","tp","fp","fn","precision","recall","f1"]]
df_metricas=df_metricas.sort_values(by=["scanner","image"]).reset_index(drop=True)

st.dataframe(
    df_metricas,
    use_container_width=True,
    hide_index=True,
    column_config={
        "scanner": st.column_config.TextColumn("Escáner"),
        "image": st.column_config.TextColumn("Imagen"),
        "tp":st.column_config.NumberColumn("TP", format="%d"),
        "fp":st.column_config.NumberColumn("FP", format="%d"),
        "fn":st.column_config.NumberColumn("FN", format="%d"),
        "precision":st.column_config.NumberColumn("Precision", format="%.4f"),
        "recall": st.column_config.NumberColumn("Recall", format="%.4f"),
        "f1":st.column_config.NumberColumn("F1", format="%.4f"),
    },
)

st.caption(
    "P/R/F1 calculados contra el ground truth del umbral seleccionado. "
    "TP: vulnerabilidades del GT detectadas. FP: detecciones del escáner no presentes en el GT. "
    "FN: vulnerabilidades del GT no detectadas por el escáner."
)
st.markdown("---")

# Concordancia entre escáneres
st.subheader("Concordancia entre escáneres (sobre la unión de detecciones)")

cohen_data = api_client.get_cohen()
assert isinstance(cohen_data, list)

st.markdown("**Cohen kappa (pareado)**")
df_cohen=pd.DataFrame(cohen_data)
df_cohen["par"]=df_cohen["scanner_a"].str.capitalize() + " - " + df_cohen["scanner_b"].str.capitalize()
df_cohen = df_cohen[["par","kappa"]]

st.dataframe(
    df_cohen,
    use_container_width=True,
    hide_index=True,
    column_config={
        "par": st.column_config.TextColumn("Par de escáneres"),
        "kappa": st.column_config.NumberColumn("κ", format="%.4f"),
    },
)
st.caption(
    "Cohen kappa pareado entre cada par de escáneres, calculado sobre la unión "
    "de las detecciones (no sobre el GT) para evitar circularidad metodológica. "
    "Escala (Landis-Koch 1977): < 0 peor que azar, 0–0.20 pobre, 0.21–0.40 razonable, "
    "0.41–0.60 moderado, 0.61–0.80 sustancial, 0.81–1.00 casi perfecto. "
    "Valor independiente del umbral del GT por construcción."
)

st.markdown("**Fleiss kappa (multi-evaluador)**")

fleiss_data = api_client.get_fleiss()
assert isinstance(fleiss_data, dict)

st.metric(
    label= "κ (Fleiss)",
    value=f"{fleiss_data['kappa']:.4f}",
)
st.caption(
    f"Fleiss kappa multi-evaluador para los 3 escáneres simultáneamente ({fleiss_data['scanners']}). "
    "Generaliza Cohen kappa a N evaluadores. Calculado también sobre la unión de detecciones. "
    "El valor negativo refleja que el desacuerdo dominante entre los tres escáneres está "
    "alineado con lo predicho por sus kappas pareados."
)

st.markdown("---")
st.caption("Trabajo de Fin de Grado · Grado en Informática · URJC · 2026")