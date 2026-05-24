def _infer_category_by_swc(swc_id: str, title: str) -> str:
    """Clasifica el hallazgo en una de las cuatro categorías del estado del arte."""
    if not swc_id:
        return "execution"
        
    swc_clean = swc_id if swc_id.startswith("SWC-") else f"SWC-{swc_id}"

    categories_map = {
        "access_control": {"SWC-105", "SWC-106", "SWC-112", "SWC-115", "SWC-124", "SWC-130"},
        "economic": {"SWC-107", "SWC-114", "SWC-113"},
        "business_logic": {"SWC-131", "SWC-135"}
    }

    if swc_clean in categories_map["access_control"] or "access" in title.lower():
        return "access_control"
    elif swc_clean in categories_map["economic"] or "reentrancy" in title.lower():
        return "economic"
    elif swc_clean in categories_map["business_logic"] or "logic" in title.lower():
        return "business_logic"
    
    return "execution"


def normalize_mythril_output(raw_output: dict) -> dict:
    """
    Procesa el diccionario proveniente de Mythril y genera un nuevo diccionario (JSON)
    con una lista uniforme de hallazgos normalizados.
    """
    # Inicializamos la estructura del JSON de salida
    normalized_report = {
        "tool": "mythril",
        "findings": []
    }

    # Validamos que la entrada contenga la estructura del runner y datos crudos válidos
    if not raw_output or not raw_output.get("success"):
        return normalized_report

    issues = raw_output.get("issues", []) if isinstance(raw_output, dict) else []

    for issue in issues:
        # Extraer y estructurar el SWC ID
        raw_swc = issue.get("swc-id")
        swc_id = f"SWC-{raw_swc}" if raw_swc and not str(raw_swc).startswith("SWC") else str(raw_swc) if raw_swc else None

        # Mapeo de parámetros informativos
        title = issue.get("title", "Unknown Vulnerability")
        category = _infer_category_by_swc(swc_id or "", title)

        # Construcción del diccionario estructurado para el hallazgo individual
        finding_dict = {
            "title": title,
            "description": issue.get("description", ""),
            "severity": issue.get("severity", "informational"),
            "category": category,
            "location": {
                "file": issue.get("filename", "unknown"),
                "line": int(issue.get("lineno", 0))
            },
            "swc_id": swc_id,
            "raw": issue  # Datos adicionales específicos preservados íntegramente
        }

        normalized_report["findings"].append(finding_dict)

    return normalized_report