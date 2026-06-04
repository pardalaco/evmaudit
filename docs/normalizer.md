# Módulo normalizer.py

Este módulo convierte la salida cruda de las herramientas de análisis (Slither y Mythril) a un formato común y estructurado que puede ser procesado por el correlator.

## Formato de salida común

Ambas funciones de normalización producen el mismo formato de salida:
```json
{
  "tool": "mythril" | "slither",
  "findings": [
    {
      "title":       str,   // nombre de la vulnerabilidad
      "description": str,   // descripción detallada
      "severity":    str,   // "high" | "medium" | "low" | "informational"  (siempre minúscula)
      "category":    str,   // "economic" | "access_control" | "business_logic" | "execution"
      "contract":    str,   // nombre del contrato afectado
      "function":    str,   // nombre de la función afectada (sin parámetros)
      "location":    dict,  // { "file": str, "line": int }  o  { "file": str, "lines": [int] }
      "swc_id":      str,   // código SWC en formato "SWC-107"
      "raw":         dict,  // hallazgo original sin modificar (para trazabilidad)
    }
  ]
}
```

Este formato común es el que recibe el correlator para cruzar hallazgos de las dos herramientas y calcular el confidence_score.

## Funciones

### `_save_json(data: dict, contract_path: str, tool: str) -> Path`
Guarda el output normalizado en la carpeta del contrato.
Estructura: `jsons/{contrato}/{contrato}_{tool}_normalizado.json`
Ejemplo: `Reentrancy + slither → jsons/Reentrancy/Reentrancy_slither_normalizado.json`

### `SLITHER_TO_SWC: dict[str, str]`
Tabla de traducción que mapea nombres de detectores de Slither a códigos SWC.
Los detectores que no tienen SWC asignado (como `solc-version` o `low-level-calls`) se descartan porque no representan vulnerabilidades explotables.

### `_infer_category_by_swc(swc_id: str, title: str) -> str`
Clasifica un hallazgo en una de las cuatro categorías del estado del arte a partir de su SWC ID:
- `access_control`: quién puede llamar a qué (SWC-105, 106, 112, 115, 124, 130)
- `economic`: manipulación de fondos o reentrancia (SWC-107, 113, 114)
- `business_logic`: errores en la lógica del contrato (SWC-131, 135)
- `execution`: resto (aritmética, timestamps, aleatoriedad, etc.)

Si no hay SWC, usa el título como fallback.

### `normalize_mythril_output(raw_output: dict) -> dict`
Normaliza la salida cruda de `run_mythril()` al formato común.
Procesa las issues de Mythril, formatea el SWC de número a formato "SWC-XXX", extrae el nombre de función sin parámetros y guarda el resultado en `jsons/{contrato}/{contrato}_mythril_normalizado.json`.

### `normalize_slither_output(raw_output: dict) -> dict`
Normaliza la salida cruda de `run_slither()` al formato común.
Procesa los detectors de Slither, traduce el nombre del detector a SWC usando la tabla `SLITHER_TO_SWC`, extrae el nombre de función y contrato de los elements, y guarda el resultado en `jsons/{contrato}/{contrato}_slither_normalizado.json`.

Los detectores sin SWC conocido (solc-version, low-level-calls...) se descartan.

### Funciones auxiliares privadas

#### `_extract_function(detector: dict) -> str`
Devuelve el nombre de la primera función encontrada en los elements de un detector de Slither.

#### `_extract_contract(detector: dict) -> str`
Devuelve el nombre del contrato afectado buscando en el campo 'parent' de los elements o directamente en elements de tipo 'contract'.

#### `_extract_lines(detector: dict) -> list[int]`
Devuelve las líneas de código de la función afectada, sin duplicados y ordenadas.
Solo toma las líneas del element de tipo 'function' para evitar repetir líneas de sub-expresiones internas.