"""
Cliente HTTP del dashboard hacia la API REST. Cada función envuelve una llamada a un endpoint de la API y devuelve el JSON parseado, con caché de Streamlit para evitar peticiones redundantes al cambiar de umbral.
"""