# Módulo correlator.py

Este módulo recibe los outputs normalizados de Slither y Mythril y los cruza para detectar coincidencias entre las herramientas y generar un informe consolidado con métricas de confianza.

## Funcionalidad principal

El correlator agrupa hallazgos que se refieren a la misma vulnerabilidad (mismo contrato, función y SWC) y:
- Calcula un `confidence_score`: 3 si ambas herramientas lo detectaron, 2 si solo una
- Asigna un `status`: "confirmed" si lo detectaron las dos herramientas, "detected" si solo una
- Toma la severidad máxima entre las dos herramientas
- Une las líneas de código de ambas herramientas (sin duplicados)
- Fusiona las evidencias de ambas herramientas en un único diccionario

El resultado se guarda en: `jsons/{contrato}/{contrato}_correlacionado.json`

## Constantes

### `SWC_TO_VULN: dict[str, str]`
Mapea códigos SWC a tipos de vulnerabilidad legibles para el campo `vuln_type`:
- SWC-101: integer_overflow
- SWC-104: unchecked_call
- SWC-105: unprotected_withdrawal
- SWC-106: unprotected_selfdestruct
- SWC-107: reentrancy
- SWC-109: uninitialized_storage
- SWC-112: delegatecall
- SWC-113: dos
- SWC-115: tx_origin_auth
- SWC-116: timestamp_dependence
- SWC-119: shadowing
- SWC-120: weak_randomness
- SWC-124: arbitrary_storage
- SWC-129: tautology
- SWC-132: locked_ether

### `SEVERITY_ORDER: dict[str, int]`
Define el orden numérico para calcular la severidad máxima:
- informational/optimization: 0
- low: 1
- medium: 2
- high: 3

## Funciones

### `_save_json(data: dict, contract_path: str) -> Path`
Guarda el resultado correlacionado en la carpeta del contrato.
Estructura: `jsons/{contrato}/{contrato}_correlacionado.json`

### `_extract_findings(normalized: dict, tool: str) -> list[dict]`
Convierte los findings del formato normalizado al formato interno del correlator.
- Añade el nombre de la herramienta a cada finding
- Homogeneiza la localización: Slither usa `location.lines` (lista), Mythril usa `location.line` (entero), ambos se convierten a lista

### `_merge_findings(slither_findings: list[dict], mythril_findings: list[dict]) -> list[dict]`
Cruza los hallazgos de ambas herramientas agrupando por (contrato, función, swc_id).
Para cada grupo:
- Si aparece en ambas herramientas: `status = "confirmed"`, `confidence_score = 3`
- Si aparece solo en una: `status = "detected"`, `confidence_score = 2`
- `severity` = el máximo entre las dos herramientas (según SEVERITY_ORDER)
- `lines` = unión ordenada de las líneas de ambas herramientas
- `evidence` = diccionario con las evidencias de cada herramienta
- `confirmed_by` = lista de herramientas que detectaron el hallazgo

### `correlate(slither_normalized: dict, mythril_normalized: dict, contract_path: str) -> dict`
Punto de entrada del correlator.
1. Extrae los findings de ambos outputs normalizados
2. Los fusiona usando `_merge_findings`
3. Construye el resultado final con el nombre del contrato y la lista de findings fusionados
4. Guarda el resultado en disco y lo devuelve

El formato de salida es:
```json
{
  "contract": "VulnerableBank",
  "findings": [
    {
      "contract": "VulnerableBank",
      "function": "withdraw",
      "swc_id": "SWC-107",
      "vuln_type": "reentrancy",
      "severity": "high",
      "confidence_score": 3,
      "status": "confirmed",
      "lines": [11, 12, 13, 14, 15, 16],
      "confirmed_by": ["mythril", "slither"],
      "evidence": {
        "slither": { "title": "...", "description": "..." },
        "mythril": { "title": "...", "description": "..." }
      }
    }
  ]
}
```