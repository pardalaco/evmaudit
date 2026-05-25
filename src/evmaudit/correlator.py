"""
correlator.py

Recibe los outputs normalizados de Slither y Mythril y los cruza para:
  - Agrupar hallazgos que se refieren a la misma vulnerabilidad (mismo contrato + función + SWC)
  - Calcular confidence_score: 3 si ambas herramientas lo detectaron, 2 si solo una
  - Asignar status: "confirmed" si lo detectaron las dos, "detected" si solo una
  - Tomar la severidad máxima entre las dos herramientas

El resultado se guarda en: jsons/{contrato}/{contrato}_correlacionado.json

Lógica de merge_findings basada en la implementación de Daniel Rovira,
adaptada para recibir findings ya normalizados en lugar de leer ficheros crudos.
"""

import json
from pathlib import Path
from collections import defaultdict


# Traduce SWC ID a nombre de tipo de vulnerabilidad para el campo vuln_type
SWC_TO_VULN: dict[str, str] = {
    "SWC-101": "integer_overflow",
    "SWC-104": "unchecked_call",
    "SWC-105": "unprotected_withdrawal",
    "SWC-106": "unprotected_selfdestruct",
    "SWC-107": "reentrancy",
    "SWC-109": "uninitialized_storage",
    "SWC-112": "delegatecall",
    "SWC-113": "dos",
    "SWC-115": "tx_origin_auth",
    "SWC-116": "timestamp_dependence",
    "SWC-119": "shadowing",
    "SWC-120": "weak_randomness",
    "SWC-124": "arbitrary_storage",
    "SWC-129": "tautology",
    "SWC-132": "locked_ether",
}

# Orden numérico para calcular la severidad máxima entre dos herramientas
SEVERITY_ORDER: dict[str, int] = {
    "informational": 0,
    "optimization": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


def _save_json(data: dict, contract_path: str) -> Path:
    """Guarda el resultado correlacionado en la carpeta del contrato."""
    contract_stem = Path(contract_path).stem
    out_dir = Path("jsons") / contract_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{contract_stem}_correlacionado.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return out_path


def _extract_findings(normalized: dict, tool: str) -> list[dict]:
    """
    Convierte los findings del formato normalizado al formato interno del correlator.

    El formato normalizado tiene 'tool' a nivel de report, no de finding,
    así que lo recibimos como parámetro y lo añadimos a cada finding.

    Para la localización:
      - Slither devuelve location.lines (lista)
      - Mythril devuelve location.line (entero)
    Los homogeneizamos siempre a lista.
    """
    findings = []
    for f in normalized.get("findings", []):
        location = f.get("location", {})
        # Homogeneizar: Slither usa "lines" (lista), Mythril usa "line" (entero)
        lines = location.get("lines") or ([location["line"]] if location.get("line") else [])

        findings.append({
            "contract": f.get("contract", "unknown"),
            "function": f.get("function", "unknown"),
            "swc_id": f.get("swc_id"),
            "vuln_type": SWC_TO_VULN.get(f.get("swc_id", ""), f.get("category", "unknown")),
            "severity": f.get("severity", "informational"),
            "lines": lines,
            "tool": tool,
            "evidence": {
                tool: {
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "function": f.get("function"),
                    "raw": f.get("raw"),
                }
            }
        })
    return findings


def _merge_findings(slither_findings: list[dict], mythril_findings: list[dict]) -> list[dict]:
    """
    Cruza los hallazgos de ambas herramientas agrupando por (contrato, función, swc_id).

    Si el mismo (contrato, función, SWC) aparece en las dos herramientas:
      - status = "confirmed"
      - confidence_score = 3
      - severity = máxima de las dos
      - lines = unión de las líneas de ambas

    Si solo aparece en una:
      - status = "detected"
      - confidence_score = 2

    Basado en merge_findings() de Daniel Rovira.
    """
    grouped = defaultdict(list)

    for finding in slither_findings + mythril_findings:
        # Agrupamos por contrato + función + SWC para detectar coincidencias exactas
        key = (finding["contract"], finding["function"], finding["swc_id"])
        grouped[key].append(finding)

    merged = []

    for (contract, function, swc_id), items in grouped.items():
        tools = sorted(set(item["tool"] for item in items))

        severity = max(
            (item["severity"] for item in items),
            key=lambda s: SEVERITY_ORDER.get(s, 0),
        )

        lines = sorted(set(
            line
            for item in items
            for line in item.get("lines", [])
        ))

        # Fusionamos las evidencias de las dos herramientas en un único dict
        evidence = {}
        for item in items:
            evidence.update(item.get("evidence", {}))

        merged.append({
            "contract": contract,
            "function": function,
            "swc_id": swc_id,
            "vuln_type": items[0]["vuln_type"],
            "severity": severity,
            "confidence_score": 3 if len(tools) >= 2 else 2,
            "status": "confirmed" if len(tools) >= 2 else "detected",
            "lines": lines,
            "confirmed_by": tools,
            "evidence": evidence,
        })

    return merged


def correlate(slither_normalized: dict, mythril_normalized: dict, contract_path: str) -> dict:
    """
    Punto de entrada del correlator.

    Recibe los dos outputs normalizados (de normalize_slither_output y
    normalize_mythril_output), los cruza y guarda el resultado en disco.

    Devuelve un dict con:
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
            "lines": [11, 12, ..., 19],
            "confirmed_by": ["mythril", "slither"],
            "evidence": {
              "slither": { ... },
              "mythril": { ... }
            }
          }
        ]
      }
    """
    slither_findings = _extract_findings(slither_normalized, "slither")
    mythril_findings = _extract_findings(mythril_normalized, "mythril")

    merged = _merge_findings(slither_findings, mythril_findings)

    contract_stem = Path(contract_path).stem
    result = {
        "contract": contract_stem,
        "findings": merged,
    }

    _save_json(result, contract_path)

    return result
