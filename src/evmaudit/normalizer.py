"""
normalizer.py

Convierte la salida cruda de cada herramienta de análisis (Mythril, Slither)
a un formato común y estructurado.

Cada herramienta produce un JSON con estructura diferente:
  - Mythril: { "success": True, "issues": [ { "swc-id", "severity", "lineno", ... } ] }
  - Slither: { "tool", "success", "raw": { "results": { "detectors": [ { "check", "impact", "elements": [...] } ] } } }

Las dos funciones de normalización producen el mismo formato de salida:
  {
    "tool": "mythril" | "slither",
    "findings": [
      {
        "title":       str,   nombre de la vulnerabilidad
        "description": str,   descripción detallada
        "severity":    str,   "high" | "medium" | "low" | "informational"  (siempre minúscula)
        "category":    str,   "economic" | "access_control" | "business_logic" | "execution"
        "contract":    str,   nombre del contrato afectado
        "function":    str,   nombre de la función afectada (sin parámetros)
        "location":    dict,  { "file": str, "line": int }  o  { "file": str, "lines": [int] }
        "swc_id":      str,   código SWC en formato "SWC-107"
        "raw":         dict,  hallazgo original sin modificar (para trazabilidad)
      }
    ]
  }

Este formato común es el que recibe el correlator para cruzar hallazgos
de las dos herramientas y calcular el confidence_score.
"""

import json
from pathlib import Path


def _save_json(data: dict, contract_path: str, tool: str) -> Path:
    """
    Guarda el output normalizado en la carpeta del contrato.

    Estructura: jsons/{contrato}/{contrato}_{tool}_normalizado.json
    Ejemplo: Reentrancy + slither → jsons/Reentrancy/Reentrancy_slither_normalizado.json
    """
    contract_stem = Path(contract_path).stem
    out_dir = Path("jsons") / contract_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{contract_stem}_{tool}_normalizado.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return out_path


# ---------------------------------------------------------------------------
# Tabla de traducción: nombre de detector de Slither → código SWC
#
# Slither devuelve un campo "check" con el nombre del detector.
# El estándar SWC (Smart Contract Weakness Classification) es el lenguaje
# común que usamos en el correlator y el catálogo de Echidna.
# Los detectores que no tienen SWC asignado (solc-version, low-level-calls...)
# se descartan en la normalización porque no representan vulnerabilidades reales.
# ---------------------------------------------------------------------------
SLITHER_TO_SWC: dict[str, str] = {
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107",
    "reentrancy-unlimited-gas": "SWC-107",
    "arbitrary-send-eth": "SWC-105",
    "arbitrary-send-erc20": "SWC-105",
    "unchecked-lowlevel": "SWC-104",
    "unchecked-send": "SWC-104",
    "suicidal": "SWC-106",
    "uninitialized-state": "SWC-109",
    "uninitialized-local": "SWC-109",
    "controlled-delegatecall": "SWC-112",
    "calls-loop": "SWC-113",
    "msg-value-loop": "SWC-113",
    "tx-origin": "SWC-115",
    "timestamp": "SWC-116",
    "shadowing-state": "SWC-119",
    "shadowing-local": "SWC-119",
    "weak-prng": "SWC-120",
    "arbitrary-storage-location": "SWC-124",
    "tautology": "SWC-129",
    "locked-ether": "SWC-132",
}


def _infer_category_by_swc(swc_id: str, title: str) -> str:
    """
    Clasifica un hallazgo en una de las cuatro categorías del estado del arte
    a partir de su SWC ID. Si no hay SWC, usa el título como fallback.

    Categorías:
      - access_control  : quién puede llamar a qué (SWC-105, 106, 112, 115, 124)
      - economic        : manipulación de fondos o reentrancia (SWC-107, 113, 114)
      - business_logic  : errores en la lógica del contrato (SWC-131, 135)
      - execution       : resto (aritmética, timestamps, aleatoriedad, etc.)
    """
    if not swc_id:
        return "execution"

    swc_clean = swc_id if swc_id.startswith("SWC-") else f"SWC-{swc_id}"

    access_control = {"SWC-105", "SWC-106", "SWC-112", "SWC-115", "SWC-124", "SWC-130"}
    economic = {"SWC-107", "SWC-114", "SWC-113"}
    business_logic = {"SWC-131", "SWC-135"}

    if swc_clean in access_control or "access" in title.lower():
        return "access_control"
    elif swc_clean in economic or "reentrancy" in title.lower():
        return "economic"
    elif swc_clean in business_logic or "logic" in title.lower():
        return "business_logic"

    return "execution"


def normalize_mythril_output(raw_output: dict) -> dict:
    """
    Normaliza la salida cruda de run_mythril() al formato común.

    Entrada esperada (output de run_mythril):
      {
        "success": True,
        "error": null,
        "issues": [
          {
            "swc-id": "107",
            "title": "...",
            "severity": "High",
            "contract": "VulnerableBank",
            "function": "withdraw(uint256)",
            "filename": "contracts/...",
            "lineno": 18,
            "description": "...",
            "tx_sequence": { ... }
          }
        ]
      }

    Salida: formato común descrito en el módulo (ver cabecera del archivo).
    """
    normalized_report = {
        "tool": "mythril",
        "findings": []
    }

    if not raw_output or not raw_output.get("success"):
        return normalized_report

    issues = raw_output.get("issues", []) if isinstance(raw_output, dict) else []

    for issue in issues:
        # Mythril devuelve el SWC como número ("107"), lo formateamos a "SWC-107"
        raw_swc = issue.get("swc-id")
        swc_id = f"SWC-{raw_swc}" if raw_swc and not str(raw_swc).startswith("SWC") else str(raw_swc) if raw_swc else None

        title = issue.get("title", "Unknown Vulnerability")
        category = _infer_category_by_swc(swc_id or "", title)

        # Mythril incluye los parámetros en el nombre de función: "withdraw(uint256)" → "withdraw"
        raw_func = issue.get("function", "unknown")
        function_name = raw_func.split("(")[0] if "(" in raw_func else raw_func

        normalized_report["findings"].append({
            "title": title,
            "description": issue.get("description", ""),
            "severity": issue.get("severity", "informational").lower(),
            "category": category,
            "contract": issue.get("contract", "unknown"),
            "function": function_name,
            "location": {
                "file": issue.get("filename", "unknown"),
                "line": int(issue.get("lineno", 0))
            },
            "swc_id": swc_id,
            "raw": issue,
        })

    # Extraemos el path del contrato del primer issue para nombrar el fichero
    contract_path = raw_output.get("issues", [{}])[0].get("filename", "unknown") if normalized_report["findings"] else "unknown"
    _save_json(normalized_report, contract_path, "mythril")

    return normalized_report


def normalize_slither_output(raw_output: dict) -> dict:
    """
    Normaliza la salida cruda de run_slither() al formato común.

    Entrada esperada (output de run_slither):
      {
        "tool": "slither",
        "contract_path": "contracts/Reentrancy.sol",
        "success": True,
        "returncode": 255,
        "raw": {
          "results": {
            "detectors": [
              {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "...",
                "elements": [
                  {
                    "type": "function",
                    "name": "withdraw",
                    "source_mapping": { "lines": [11, 12, ...] },
                    "type_specific_fields": {
                      "parent": { "type": "contract", "name": "VulnerableBank" }
                    }
                  }
                ]
              }
            ]
          }
        }
      }

    Slither devuelve returncode 255 cuando encuentra vulnerabilidades (no es un error),
    por eso success puede ser True con returncode != 0.

    Los detectores sin SWC conocido (solc-version, low-level-calls...) se descartan.

    Salida: formato común descrito en el módulo (ver cabecera del archivo).
    """
    normalized_report = {
        "tool": "slither",
        "findings": []
    }

    if not raw_output:
        return normalized_report

    detectors = raw_output

    for detector in detectors:
        check = detector.get("check", "")
        swc_id = SLITHER_TO_SWC.get(check)

        # Descartamos detectores sin SWC (informativos, de estilo, versión de compilador...)
        if not swc_id:
            continue

        impact = detector.get("impact", "Informational")
        # La descripción de Slither es multilínea; la primera línea es el resumen
        title = detector.get("description", "").split("\n")[0].strip()
        category = _infer_category_by_swc(swc_id, check)

        contract_name = _extract_contract(detector)
        function_name = _extract_function(detector)
        lines = _extract_lines(detector)

        normalized_report["findings"].append({
            "title": title,
            "description": detector.get("description", "").strip(),
            "severity": impact.lower(),
            "category": category,
            "contract": contract_name,
            "function": function_name,
            "location": {
                "file": raw_output.get("contract_path", "unknown"),
                "lines": lines,
            },
            "swc_id": swc_id,
            "raw": detector,
        })

    _save_json(normalized_report, raw_output.get("contract_path", "unknown"), "slither")

    return normalized_report


# ---------------------------------------------------------------------------
# Helpers privados para extraer campos de los elements de Slither.
#
# Slither estructura cada hallazgo como una lista de "elements" (nodos del AST):
# funciones, contratos, nodos de expresión, etc. Hay que recorrerlos para
# encontrar el nombre de la función y del contrato afectados.
# ---------------------------------------------------------------------------

def _extract_function(detector: dict) -> str:
    """Devuelve el nombre de la primera función encontrada en los elements."""
    for element in detector.get("elements", []):
        if element.get("type") == "function":
            return element.get("name", "unknown")
    return "unknown"


def _extract_contract(detector: dict) -> str:
    """
    Devuelve el nombre del contrato afectado.
    Lo busca en el campo 'parent' de los elements (que apunta al contrato contenedor)
    o directamente en elements de tipo 'contract'.
    """
    for element in detector.get("elements", []):
        parent = element.get("type_specific_fields", {}).get("parent", {})
        if parent.get("type") == "contract" and parent.get("name"):
            return parent["name"]
        if element.get("type") == "contract" and element.get("name"):
            return element["name"]
    return "unknown"


def _extract_lines(detector: dict) -> list[int]:
    """
    Devuelve las líneas de código de la función afectada, sin duplicados y ordenadas.
    Solo toma las líneas del element de tipo 'function' (no de los nodos internos)
    para evitar repetir líneas de sub-expresiones.
    """
    lines = []
    for element in detector.get("elements", []):
        if element.get("type") == "function":
            lines += element.get("source_mapping", {}).get("lines", [])
    return sorted(set(lines))
