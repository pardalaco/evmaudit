# Módulo reporter.py

Este módulo genera el informe final del análisis combinando los resultados de las tres herramientas (Slither, Mythril y Echidna) y produce dos artefactos:
- `{contrato}_report.json` — datos estructurados para integración en otros sistemas
- `{contrato}_report.md` — informe legible en Markdown para el auditor

## Funcionalidad principal

El informe consolida:
- Resumen ejecutivo: contrato analizado, herramientas usadas, totales
- Tabla de hallazgos correlacionados con severidad, confianza y estado
- Resultados de Echidna por propiedad (passed / failed / no-testable)
- Advertencias sobre propiedades no testables automáticamente (Opción B)
- Puntuación de riesgo global (0–10)

## Constantes

### `SEVERITY_WEIGHT: dict[str, int]`
Peso de cada nivel de severidad para el cálculo del risk score:
- high: 10
- medium: 5
- low: 2
- informational/optimization: 0

### `SEVERITY_ICON: dict[str, str]`
Emojis de severidad para el Markdown:
- high: 🔴
- medium: 🟠
- low: 🟡
- informational/optimization: ⚪

### `STATUS_LABEL: dict[str, str]`
Etiquetas de estado del correlator:
- confirmed: "CONFIRMADO (ambas herramientas)"
- detected: "DETECTADO (una herramienta)"

## Funciones

### `_risk_score(findings: list[dict]) -> float`
Calcula una puntuación de riesgo global entre 0 y 10.
Fórmula: suma ponderada por severidad × confidence_score, normalizada a 10.
Un contrato con 3 high confirmed = 10/10.

### `_echidna_summary(echidna_output: dict, adapter_meta: dict) -> list[dict]`
Cruza los resultados de Echidna con los metadatos del adapter.
Para cada propiedad echidna_*:
- Si Echidna la ejecutó: indica passed / failed
- Si estaba marcada como no testable: añade advertencia
- Si Echidna no devolvió resultado: marca como sin_resultado

### `_build_json_report(contract_path: str, correlator_output: dict, echidna_output: dict, adapter_meta: dict) -> dict`
Construye el dict con todos los datos del informe.
Incluye metadatos, resumen ejecutivo, findings correlacionados y resultados de Echidna.

### `_build_markdown_report(report: dict) -> str`
Genera el informe en formato Markdown a partir del dict del informe.
Construye cada sección iterando los findings y los resultados de Echidna.
Las propiedades no testables se deduplican por (función, swc_id) para que la misma advertencia no aparezca múltiples veces.

Estructura del informe Markdown:
```
# Informe de Análisis — {contrato}
## Resumen ejecutivo
   - Tabla con totales: hallazgos, confirmed/detected, alta severidad
   - Puntuación de riesgo [████████░░] 8.3/10
## Hallazgos correlacionados
   - Tabla: función | SWC | tipo | severidad | confianza | estado
## Detalle de hallazgos
   - Por cada finding: descripción, líneas, evidencia de cada herramienta
## Resultados de Echidna
   - Tabla: función | SWC | detector | testable | resultado
   - Advertencias para propiedades no testables (deduplicadas por función)
## Recomendaciones
   - Alta prioridad (high severity)
   - Media prioridad (medium severity)
   - Auditoría manual recomendada (si hay no-testables)
```

### `generate_report(contract_path: str, correlator_output: dict, echidna_output: dict = None, adapter_meta: dict = None) -> dict`
Punto de entrada del reporter.

Parámetros:
- `contract_path`: ruta al .sol original analizado
- `correlator_output`: dict devuelto por correlate()
- `echidna_output`: dict devuelto por run_echidna() (opcional)
- `adapter_meta`: dict devuelto por echidna_adapter.generate() (opcional)

Devuelve el dict con el informe completo y guarda en disco:
- `jsons/{contrato}/{contrato}_report.json`
- `jsons/{contrato}/{contrato}_report.md`

Si no se proporcionan `echidna_output` y `adapter_meta`, el informe se genera igualmente con los resultados de Slither y Mythril únicamente.