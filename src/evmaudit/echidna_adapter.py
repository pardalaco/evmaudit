"""
echidna_adapter.py

Recibe el output del correlator y genera automáticamente un contrato Solidity
wrapper listo para ejecutar con Echidna.

Para cada finding correlacionado:
  1. Traduce el swc_id al detector de Slither equivalente (via swc_catalog)
  2. Obtiene la plantilla echidna_* correspondiente del catálogo
  3. Sustituye {func} por el nombre de la función vulnerable
  4. Genera un contrato wrapper que hereda del original con todas las propiedades

Opción B para vulnerabilidades no testables (echidna_testable=False):
  - Se incluye la propiedad en el wrapper igualmente (para documentación)
  - Se añade un comentario de advertencia en el .sol
  - Se marca en los metadatos devueltos para que el reporter lo indique

El wrapper se guarda en: jsons/{contrato}/{contract_name}_Echidna.sol
Y se ejecuta con: run_echidna(wrapper_path, contract_name + "_Echidna")
"""

import os
import json
import shutil
from pathlib import Path
from evmaudit.swc_catalog import CATALOG, detector_from_swc


def _generate_wrapper(contract_path: str, contract_name: str, vulnerabilities: list[dict]) -> str:
    """
    Genera el código Solidity del contrato wrapper con todas las propiedades echidna_*.

    Las propiedades de vulnerabilidades no testables se incluyen igual pero con
    un bloque de advertencia visible en el .sol para que quien lo lea sepa que
    Echidna no puede verificar reentrancia sin un contrato atacante externo.
    """
    properties = ""

    for v in vulnerabilities:
        sources = " + ".join(v["confirmed_by"])

        for det in v["detectors"]:
            entry = CATALOG[det]
            testable = entry.get("echidna_testable", True)

            if not testable:
                properties += f"""
    // =========================================================================
    // ADVERTENCIA [{v['swc_id']}] — NO TESTABLE AUTOMATICAMENTE
    // Esta propiedad NO puede verificar la vulnerabilidad real sin un contrato
    // atacante externo que re-entre en el callback. Resultado esperado: passed
    // (la invariante se cumple, pero eso no descarta la vulnerabilidad).
    // Detectado por: {sources}
    // Limitación: {entry.get('limitacion', '')}
    // =========================================================================
"""
            else:
                properties += f"\n    // [{v['swc_id']}] Detectado por: {sources}\n"

            properties += entry["plantilla"].format(func=v["function"])

    wrapper = f"""// SPDX-License-Identifier: MIT
// GENERADO AUTOMATICAMENTE por echidna_adapter.py
// No editar manualmente — regenerar ejecutando el pipeline
pragma solidity ^0.8.0;

import "./{os.path.basename(contract_path)}";

contract {contract_name}_Echidna is {contract_name} {{
{properties}
}}
"""
    return wrapper


def _save_wrapper(code: str, contract_path: str, contract_name: str) -> Path:
    """Guarda el wrapper .sol en la carpeta del contrato."""
    contract_stem = Path(contract_path).stem
    out_dir = Path("jsons") / contract_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{contract_name}_Echidna.sol"
    out_path.write_text(code)
    return out_path


def _save_metadata(metadata: dict, contract_path: str, contract_name: str) -> Path:
    """Guarda los metadatos del adapter (para el reporter) en disco."""
    contract_stem = Path(contract_path).stem
    out_dir = Path("jsons") / contract_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{contract_stem}_adapter.json"
    out_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False))
    return out_path


def generate(correlator_output: dict, contract_path: str, contract_name: str) -> dict:
    """
    Punto de entrada del adapter.

    Recibe el output del correlator y genera el contrato wrapper para Echidna.

    Parámetros:
      correlator_output : dict devuelto por correlate()
      contract_path     : ruta al .sol original (para el import del wrapper)
      contract_name     : nombre del contrato Solidity (ej: "VulnerableBank")

    Devuelve un dict con:
      {
        "wrapper_path": str | None,         # ruta al .sol generado
        "contract_name_echidna": str,        # nombre del contrato wrapper
        "vulnerabilities": [
          {
            "swc_id": str,
            "function": str,
            "detectors": [str],
            "confirmed_by": [str],
            "echidna_testable": bool,        # False → propiedad incluida con advertencia
            "warning": str | None            # descripción de la limitación si no testable
          }
        ],
        "testable_count": int,
        "non_testable_count": int,
        "skipped_count": int,               # SWC sin soporte en el catálogo
      }

    Las vulnerabilidades sin plantilla en el catálogo se omiten (skipped).
    Las no testables se incluyen en el wrapper con advertencia (Opción B).
    """
    findings = correlator_output.get("findings", [])

    vulnerabilities = []
    skipped = 0

    for finding in findings:
        swc_id = finding.get("swc_id", "")
        function = finding.get("function", "unknown")
        confirmed_by = finding.get("confirmed_by", [])

        # Traducir SWC → detectores de Slither para buscar en el catálogo
        detectors = [d for d in detector_from_swc(swc_id) if d in CATALOG]

        if not detectors:
            print(f"  [!] Sin plantilla para {swc_id} en {function}() — omitido")
            skipped += 1
            continue

        # Opción B: incluir siempre, marcar testabilidad
        testable = all(CATALOG[d].get("echidna_testable", True) for d in detectors)
        warning = None
        if not testable:
            limitations = [CATALOG[d].get("limitacion", "") for d in detectors if not CATALOG[d].get("echidna_testable", True)]
            warning = limitations[0] if limitations else "Requiere contrato atacante externo."

        vulnerabilities.append({
            "swc_id": swc_id,
            "function": function,
            "confirmed_by": confirmed_by,
            "detectors": detectors,
            "echidna_testable": testable,
            "warning": warning,
        })

    testable_count = sum(1 for v in vulnerabilities if v["echidna_testable"])
    non_testable_count = sum(1 for v in vulnerabilities if not v["echidna_testable"])

    if not vulnerabilities:
        print("  [!] No se encontraron vulnerabilidades con plantilla. No se genera wrapper.")
        metadata = {
            "wrapper_path": None,
            "contract_name_echidna": f"{contract_name}_Echidna",
            "vulnerabilities": [],
            "testable_count": 0,
            "non_testable_count": 0,
            "skipped_count": skipped,
        }
        _save_metadata(metadata, contract_path, contract_name)
        return metadata

    print(f"  [+] Generando wrapper para {len(vulnerabilities)} vulnerabilidad(es):")
    for v in vulnerabilities:
        status = "ALTA CONFIANZA" if len(v["confirmed_by"]) >= 2 else v["confirmed_by"][0]
        testable_flag = "" if v["echidna_testable"] else " [NO TESTABLE — Opción B]"
        print(f"      {v['swc_id']} en {v['function']}()  [{status}]{testable_flag}")

    wrapper_code = _generate_wrapper(contract_path, contract_name, vulnerabilities)
    out_path = _save_wrapper(wrapper_code, contract_path, contract_name)

    # Copiar el contrato original a la carpeta del análisis para que el import funcione
    contract_stem = Path(contract_path).stem
    dest = Path("jsons") / contract_stem / Path(contract_path).name
    shutil.copy(contract_path, dest)

    print(f"\n  [OK] Wrapper generado: {out_path}")
    if non_testable_count:
        print(f"  [!]  {non_testable_count} propiedad(es) NO testable(s) incluidas con advertencia")
    print(f"  [→]  Ejecutar con: run_echidna(\"{out_path}\", \"{contract_name}_Echidna\")")

    metadata = {
        "wrapper_path": str(out_path),
        "contract_name_echidna": f"{contract_name}_Echidna",
        "vulnerabilities": vulnerabilities,
        "testable_count": testable_count,
        "non_testable_count": non_testable_count,
        "skipped_count": skipped,
    }
    _save_metadata(metadata, contract_path, contract_name)
    return metadata
