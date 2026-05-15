"""
Análisis estadístico de los datos obtenidos y normalizados de todo el proceso anterior

Vamos a calcular métricas de evaluación vs ground truth (ya construido), unido con medidas GT (kappas) y tests de significación. Buscamos obtener la mayor cantidad de datos a partir de lo obtenido y
responder a la pregunta central de este TFG: ¿existe una diferencia significativa entre Trivy, Grype y DockerScout?

"""
import pandas as pd
import numpy as np
from pathlib import Path
from itertools import combinations
from scipy.stats import friedmanchisquare, bootstrap

# Rutas relativas a la raíz del repo — esto solo funciona si lanzas el script desde la raíz del proyecto (decisión consciente, evita liarme con paths absolutos que no son portables)
NORMALIZED_CSV = Path("analysis/output/normalized.csv")
GROUND_TRUTH_CSV = Path("ground-truth/output/ground_truth.csv")
OUTPUT_DIR = Path("analysis/output")

# La tripleta (image, cve_id, package) es lo que define una detección
# única — misma decisión que en build_ground_truth.py
CLAVE = ["image","cve_id","package"]



############################################
############## Auxiliares ##################
############################################
def _calcular_prec_recc_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """
    Función para encapsular el cálculo de precisión, recall y F1.
    Devuelve tupla de 3 posiciones float con el resultado del cálculo de los valores.
    El _ indica que es una función auxiliar, no de la parte pública de stats.py
    """
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)
    return round(precision,4), round(recall,4), round(f1,4)

def _build_matriz_binaria(df_norm):
    """
    Para el cálculo de kappa necesitamos construir esta matriz.
    Celdas: si el escáner NO detecta vulnerabilidad 0, si SÍ 1.
    Filas: (image,cve_id,package) cada vulnerabilidad única del universo
    Columnas: cada escáner

    Llamamos universo a la unión de las detecciones de los escáneres, NO al GT. Decisión metodológica que se tuvo que tomar para evitar circularidad.
    Si hubiéramos usado el GT como universo (como se había planteado al inicio) sesgaría Kappa al alza, ya que el GT se construye por consenso de esos mismos escáneres evaluados. Documentado en memoria.
    """
    vulns_universo = sorted(set(map(tuple,df_norm[CLAVE].values)))
    scanners = sorted(df_norm["scanner"].unique())

    detecciones_por_scanner = {
        s: set(map(tuple,df_norm[df_norm["scanner"] == s][CLAVE].values))
        for s in scanners
    }

    filas = []
    for vuln in vulns_universo:
        fila = {s: 1 if vuln in detecciones_por_scanner[s] 
                    else 0 for s in scanners}
        filas.append(fila)
    return pd.DataFrame(
         filas,
         index= pd.MultiIndex.from_tuples(vulns_universo,names=CLAVE)
     )

def _calcular_cohen_kappa(col_a,col_b):
    """
    Calculamos Cohen's kappa para par de evaluadores con voto binario. Mide acuerdo entre el par corregido por azar.

    Recibimos par de columnas con el mismo índice (series pandas). Sin nombre, el cálculo es independiente de él.
    kappa = (po - pe)/(1 - pe)
    -po: acuerdo observado
    -pe: esperado por azar dadas las tasas de detección de cada escáner

    kappa < 0 peor que azar (raro)
    kappa = 0 -> acuerdo igual al azar
    kappa = 1 -> acuerdo total

    """
    n = len(col_a)

    a= ((col_a == 1) & (col_b == 1)).sum() #ambos detectan
    b= ((col_a == 1) & (col_b == 0)).sum() #solo primero detecta
    c= ((col_a == 0) & (col_b == 1)).sum() #solo segundo
    d= ((col_a == 0) & (col_b == 0)).sum() #ninguno

    po = (a + d)/n
    p_a_yes = (a+b)/n
    p_b_yes = (a+c)/n
    pe = p_a_yes * p_b_yes + (1-p_a_yes)*(1-p_b_yes)

    kappa = (po-pe)/(1-pe) if (1-pe) > 0 else 0.0

    return round(kappa, 4)


def _calcular_fleiss_kappa(matriz_bin):
    """
    El cálculo de Fleiss kappa es una extensión del multi-evaluador. Devuelve sólo 1 número para los N escáneres a la vez, en vez de N x (N-1)/2 pares de Cohen kappa.
    1 acuerdo perfecto, 0 azar.
    Calcula Fleiss sobre todas las columnas, a partir de la matriz entera
    """
    n=len(matriz_bin)
    N=matriz_bin.shape[1]

    n_scn_yes = matriz_bin.sum(axis=1)
    n_scn_no = N-n_scn_yes


    P_agre = (n_scn_yes**2 + n_scn_no**2 - N)/(N*(N-1))

    P_avg_agree= P_agre.mean()

    total_1 = matriz_bin.values.sum()
    p_1 = total_1 / (n*N)
    p_0 = 1 - p_1

    P_agree_azar = p_0**2 + p_1**2

    kappa = (P_avg_agree - P_agree_azar)/(1-P_agree_azar) if (1-P_agree_azar) > 0 else 0.0

    return round(kappa, 4)



############################################
############## PÚBLICAS ####################
############################################
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
    imagenes = sorted(set(df_norm["image"]) | set(df_gt["image"]))
    for scanner in df_norm["scanner"].unique():
        # Subset de detecciones por imagen
        df_s = df_norm[df_norm["scanner"] == scanner]        
        for image in imagenes:
            # Sets de tuplas (image, cve_id, package). TP/FP/FN se leen literalmente como las operaciones de conjunto de toda la vida.
            detectado = set(map(tuple, df_s[df_s["image"] == image][CLAVE].values))
            real = set(map(tuple, df_gt[df_gt["image"] == image][CLAVE].values))

            tp = len(detectado & real)
            fp = len(detectado - real)
            fn = len(real - detectado)
            # Guarda contra div/0 — pasa en Scout × Alpine, no es teórico: si el escáner no reporta nada en una imagen, tp+fp = 0.
            precision, recall, f1 = _calcular_prec_recc_f1(tp,fp,fn)
            
            # Redondeo a 4 decimales solo para que el CSV no quede ilegible con 17 dígitos. Para el análisis estadístico no afecta.
            filas.append({
                "scanner": scanner,
                "image": image,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            })
    return pd.DataFrame(filas)

def calcular_concordancia(df_norm):
    """
    Calculamos coeficiente de acuerdo sobre el universo de la unión de las detecciones.

    1. Construye matriz binaria (vulnerabilidad x scanner).
    2. Calcula Cohen's kappa por pares para las 3 combinaciones posibles ( [trivy/grype], [trivy/scout], [grype/scout])
    3 .Calcula Fleiss kappa para los 3 escáneres

    Devuelve un DataFrame con todos los coeficientes, formateado para su volcado a csv y posterior consumo de la API REST
    """
    matriz= _build_matriz_binaria(df_norm)
    scanners= matriz.columns.to_list()

    filas_cohens=[]
    for scan_a, scan_b in combinations(scanners, 2):
        kappa = _calcular_cohen_kappa(matriz[scan_a], matriz[scan_b])
        filas_cohens.append({
            "scanner_a": scan_a,
            "scanner_b": scan_b,
            "kappa": kappa,
        })
    df_cohens = pd.DataFrame(filas_cohens)

    fleiss = _calcular_fleiss_kappa(matriz)
    df_fleiss = pd.DataFrame([{
        "scanners": ",".join(scanners),
        "kappa": fleiss,
    }])

    return {
        "cohen": df_cohens,
        "fleiss": df_fleiss,
    }

def calcular_friedman(df_metricas):
    """"""
    # F1 por escáner, organizado por imagen
    f1_por_scanner = {}
    for scanner in sorted(df_metricas["scanner"].unique()):
        df_scann = df_metricas[df_metricas["scanner"] == scanner].sort_values("image")
        f1_por_scanner[scanner] = df_scann["f1"].values


    # Test de Friedman
    statistic , pvalue = friedmanchisquare(*f1_por_scanner.values())

    return pd.DataFrame([{
        "statistic": round(statistic , 4),
        "pvalue": round(pvalue, 6),
        "significativo": pvalue < 0.05,
        "num_imagenes": len(df_metricas["image"].unique())
    }])

def calcular_bootstrap_ci(df_metricas):



    filas=[]
    for scanner in sorted(df_metricas["scanner"].unique()):
        f1_val = df_metricas[df_metricas["scanner"] == scanner]["f1"].values

        resultado = bootstrap(
                (f1_val,),
                statistic=np.mean,
                n_resamples=9999,
                confidence_level=0.95,
                method="BCa",
                rng=42,
        )

        filas.append({
            "scanner": scanner,
            "f1_mean": round(f1_val.mean(),4),
            "f1_ci_low": round(resultado.confidence_interval.low, 4),
            "f1_ci_high": round(resultado.confidence_interval.high, 4)
        })

    return pd.DataFrame(filas)


def run():
    """cargar csv, calcular métricas y guardar resultado"""
    df_norm = pd.read_csv(NORMALIZED_CSV)
    df_gt = pd.read_csv(GROUND_TRUTH_CSV)
    metricas = calcula_metricas_scanners(df_norm, df_gt)

    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    output_path= OUTPUT_DIR / "metricas_umbral2.csv"
    metricas.to_csv(output_path, index=False)
    print(f"Guardado: {output_path} ({len(metricas)} filas)")

    # Concordancia. Cohen pareado y Fleiss agregado, cada uno en csv
    concordancia = calcular_concordancia(df_norm)
    for nombre,df in concordancia.items():
        output_path = OUTPUT_DIR/f"{nombre}_kappa.csv"
        df.to_csv(output_path, index=False)
        print(f"Guardado: {output_path} ({len(df)} filas)")


    # Test de Friedman sobre F1 pr imagen
    friedman = calcular_friedman(metricas)
    output_path = OUTPUT_DIR/"friedman.csv"
    friedman.to_csv(output_path, index=False)
    print(f"Guardado: {output_path} ({len(friedman)} filas)")

    #Bootstrap sobre F1 por cada escáner
    bootstrap_ci = calcular_bootstrap_ci(metricas)
    output_path = OUTPUT_DIR / "bootstrap_ci.csv"
    bootstrap_ci.to_csv(output_path, index=False)
    print(f"Guardado: {output_path} ({len(bootstrap_ci)} filas)")

if __name__ == "__main__":
    run()
