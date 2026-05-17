# Dashboard

Visualización interactiva del experimento comparativo Trivy/Grype/Scout. Consume la API REST del TFG y permite alternar entre los umbrales de consenso del ground truth para mostrar la inversión del ranking de escáneres.

## Arranque

Requiere la API levantada en `http://localhost:8000` (ver `api/README.md`).

```bash
# Desde la raíz del repositorio, con el .venv activo
streamlit run dashboard/app.py
```

Por defecto se abre en `http://localhost:8501`.

## Estructura

- `app.py` — punto de entrada del dashboard
- `config.py` — URL de la API, paleta de colores por escáner, constantes
- `api_client.py` — funciones de fetch a la API REST