"""
Análisis estadístico de los datos obtenidos y normalizados de todo el proceso anterior

Vamos a calcular métricas de evaluación vs ground truth (ya construido), unido con medidas GT (kappas) y tests de significación. Buscamos obtener la mayor cantidad de datos a partir de lo obtenido y
responder a la pregunta central de este TFG: ¿existe una diferencia significativa entre Trivy, Grype y DockerScout?

"""
import pandas as pd
from pathlib import Path

# Rutas relativas a la raíz del repo — esto solo funciona si lanzas el script desde la raíz del proyecto (decisión consciente, evita liarme con paths absolutos que no son portables)
NORMALIZED_CSV = Path("analysis/output/normalized.csv")
GROUND_TRUTH_CSV = Path("ground-truth/output/ground_truth.csv")
OUTPUT_DIR = Path("analysis/output")

# La tripleta (image, cve_id, package) es lo que define una detección
# única — misma decisión que en build_ground_truth.py
CLAVE = ["image","cve_id","package"]

def calcula_metricas_scanners(df_norm,df_gt):
    """
    Calcula TP, FP, FN y las tres métricas derivadas (precisión, recall, F1)
    para cada combinación (scanner, image).

    La lógica de conteo:
        TP — el escáner detectó la vuln y estaba en el GT → acierto.
        FP — el escáner la detectó pero no está en el GT → ruido.
        FN — está en el GT pero el escáner no la vio → se le escapó.

    TN no se calcula. Sería el conjunto de "vulnerabilidades que no existen
    y el escáner correctamente no reportó", algo de cardinalidad infinita
    y sin sentido práctico. Es la convención estándar en evaluación de
    seguridad y por eso F1 es la métrica de cabecera aquí, no la accuracy.

    Las tres métricas que devuelve:

        Precisión = TP / (TP + FP)
            De lo que el escáner reporta, cuánto es cierto. Mide ruido:
            precisión baja = el escáner detecta de más.

        Recall    = TP / (TP + FN)
            De lo real, cuánto detecta. Mide huecos:
            recall bajo = al escáner se le escapan cosas.

        F1        = 2·P·R / (P + R)
            Media armónica de las dos. La gracia es que penaliza el
            desbalance: si una se hunde, F1 se hunde con ella aunque
            la otra sea perfecta. Eso evita conclusiones engañosas tipo
            "Scout tiene precisión 1.0, es el mejor" cuando en realidad
            tiene recall 0.1 y se está perdiendo el 90% de las vulns.
    """
    filas = []

    for scanner in df_norm["scanner"].unique():
        # Subset de detecciones por imagen
        df_s = df_norm[df_norm["scanner"] == scanner]

        for image in df_norm["image"].unique():
            # Sets de tuplas (image, cve_id, package). TP/FP/FN se leen literalmente como las operaciones de conjunto de toda la vida.
            detectado = set(map(tuple, df_s[df_s["image"] == image][CLAVE].values))
            real = set(map(tuple, df_gt[df_gt["image"] == image][CLAVE].values))

            tp = len(detectado & real)
            fp = len(detectado - real)
            fn = len(real - detectado)
            # Guarda contra div/0 — pasa en Scout × Alpine, no es teórico: si el escáner no reporta nada en una imagen, tp+fp = 0.

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)

            # Redondeo a 4 decimales solo para que el CSV no quede ilegible con 17 dígitos. Para el análisis estadístico no afecta.
            filas.append({
                "scanner": scanner,
                "image": image,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(precision,4),
                "recall": round(recall,4),
                "f1": round(f1,4),
            })
    return pd.DataFrame(filas)

