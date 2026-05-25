"""
reporter.py

Genera el informe final del análisis de un contrato inteligente combinando
los resultados de Slither, Mythril, el correlator y Echidna.

Produce dos artefactos:
  - jsons/{contrato}/{contrato}_report.json  : datos estructurados para integración
  - jsons/{contrato}/{contrato}_report.md    : informe legible en Markdown

El informe consolida:
  - Resumen ejecutivo: contrato analizado, herramientas usadas, totales
  - Tabla de hallazgos correlacionados con severidad, confianza y estado
  - Resultados de Echidna por propiedad (passed / failed / no-testable)
  - Advertencias sobre propiedades no testables automáticamente (Opción B)
  - Puntuación de riesgo global (0–10)
"""

import json
from datetime import datetime
from pathlib import Path


# Peso de cada nivel de severidad para el risk score
SEVERITY_WEIGHT = {
    "high": 10,
    "medium": 5,
    "low": 2,
    "informational": 0,
    "optimization": 0,
}

# Emojis de severidad para el Markdown
SEVERITY_ICON = {
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "informational": "⚪",
    "optimization": "⚪",
}

# Etiquetas de estado del correlator
STATUS_LABEL = {
    "confirmed": "CONFIRMADO (ambas herramientas)",
    "detected": "DETECTADO (una herramienta)",
}


def _risk_score(findings: list[dict]) -> float:
    """
    Calcula una puntuación de riesgo global entre 0 y 10.

    Fórmula: suma ponderada por severidad × confidence_score,
    normalizada a 10. Un contrato con 3 high confirmed = 10/10.
    """
    total = sum(
        SEVERITY_WEIGHT.get(f.get("severity", "informational"), 0) * f.get("confidence_score", 2)
        for f in findings
    )
    # Referencia: 3 findings high confirmed = 3 × 10 × 3 = 90 → 10/10
    return round(min(total / 9, 10), 1)


def _echidna_summary(echidna_output: dict, adapter_meta: dict) -> list[dict]:
    """
    Cruza los resultados de Echidna con los metadatos del adapter.

    Para cada propiedad echidna_*:
      - Si Echidna la ejecutó: indica passed / failed
      - Si estaba marcada como no testable: añade advertencia
      - Si Echidna no devolvió resultado: marca como sin_resultado
    """
    if not echidna_output:
        return []

    tests = echidna_output.get("tests", [])
    tests_by_name = {t.get("name", ""): t for t in tests}

    rows = []
    for vuln in adapter_meta.get("vulnerabilities", []):
        for det in vuln.get("detectors", []):
            func = vuln["function"]
            matching = [t for name, t in tests_by_name.items() if func in name]

            if not matching:
                status = "no_ejecutado"
                passed = None
            else:
                t = matching[0]
                status = t.get("status", "sin_resultado")
                passed = t.get("passed")

            rows.append({
                "swc_id": vuln["swc_id"],
                "function": func,
                "detector": det,
                "echidna_testable": vuln["echidna_testable"],
                "warning": vuln.get("warning"),
                "echidna_status": status,
                "echidna_passed": passed,
            })

    return rows


def _build_json_report(
    contract_path: str,
    correlator_output: dict,
    echidna_output: dict,
    adapter_meta: dict,
) -> dict:
    """Construye el dict con todos los datos del informe."""
    findings = correlator_output.get("findings", [])
    echidna_rows = _echidna_summary(echidna_output, adapter_meta)
    score = _risk_score(findings)

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    detected = [f for f in findings if f.get("status") == "detected"]
    high = [f for f in findings if f.get("severity") == "high"]

    return {
        "meta": {
            "contract": Path(contract_path).stem,
            "contract_path": str(contract_path),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "tools": ["slither", "mythril", "echidna"],
        },
        "summary": {
            "total_findings": len(findings),
            "confirmed": len(confirmed),
            "detected_only": len(detected),
            "high_severity": len(high),
            "risk_score": score,
            "echidna_testable": adapter_meta.get("testable_count", 0),
            "echidna_non_testable": adapter_meta.get("non_testable_count", 0),
        },
        "findings": findings,
        "echidna_results": echidna_rows,
    }


def _build_markdown_report(report: dict) -> str:
    """Genera el informe en formato Markdown a partir del dict del informe."""
    meta = report["meta"]
    summary = report["summary"]
    findings = report["findings"]
    echidna_rows = report["echidna_results"]

    score = summary["risk_score"]
    score_bar = "█" * int(score) + "░" * (10 - int(score))

    lines = [
        f"# Informe de Análisis de Seguridad — `{meta['contract']}`",
        "",
        f"> Generado: {meta['generated_at']}  ",
        f"> Herramientas: Slither · Mythril · Echidna  ",
        f"> Contrato: `{meta['contract_path']}`",
        "",
        "---",
        "",
        "## Resumen ejecutivo",
        "",
        "| Métrica | Valor |",
        "|---------|-------|",
        f"| Total hallazgos | {summary['total_findings']} |",
        f"| Confirmados (ambas herramientas) | {summary['confirmed']} |",
        f"| Detectados (una herramienta) | {summary['detected_only']} |",
        f"| Severidad alta | {summary['high_severity']} |",
        f"| Propiedades Echidna testables | {summary['echidna_testable']} |",
        f"| Propiedades Echidna no testables | {summary['echidna_non_testable']} |",
        "",
        f"### Puntuación de riesgo global: **{score}/10**",
        "",
        "```",
        f"[{score_bar}] {score}/10",
        "```",
        "",
        "> **Nota sobre la puntuación:** se calcula como suma ponderada de severidad × confianza,",
        "> normalizada a 10. Un contrato con 3 hallazgos high confirmados = 10/10.",
        "",
        "---",
        "",
        "## Hallazgos correlacionados",
        "",
        "| # | Función | SWC | Tipo | Severidad | Confianza | Estado |",
        "|---|---------|-----|------|-----------|-----------|--------|",
    ]

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "informational")
        icon = SEVERITY_ICON.get(sev, "")
        status = STATUS_LABEL.get(f.get("status", ""), f.get("status", ""))
        score_val = f.get("confidence_score", 2)
        stars = "★" * score_val + "☆" * (3 - score_val)
        lines.append(
            f"| {i} | `{f.get('function', '?')}` | {f.get('swc_id', '?')} "
            f"| {f.get('vuln_type', '?')} | {icon} {sev} | {stars} {score_val}/3 | {status} |"
        )

    lines += [""]

    lines += [
        "---",
        "",
        "## Detalle de hallazgos",
        "",
    ]

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "informational")
        icon = SEVERITY_ICON.get(sev, "")
        confirmed_by = ", ".join(f.get("confirmed_by", []))
        lines_list = ", ".join(str(ln) for ln in f.get("lines", []))
        evidence = f.get("evidence", {})

        lines += [
            f"### {i}. `{f.get('function', '?')}()` — {f.get('swc_id', '?')} {icon}",
            "",
            f"- **Tipo:** {f.get('vuln_type', '?')}",
            f"- **Severidad:** {sev}",
            f"- **Confianza:** {f.get('confidence_score', 2)}/3 — detectado por {confirmed_by}",
            f"- **Estado:** {STATUS_LABEL.get(f.get('status', ''), f.get('status', ''))}",
            f"- **Líneas:** {lines_list if lines_list else 'no disponible'}",
            "",
        ]

        for tool, ev in evidence.items():
            if ev and ev.get("description"):
                first_line = ev.get("description", "").strip().splitlines()[0]
                lines += [
                    f"**{tool.capitalize()}:** {ev.get('title', '')}",
                    "",
                    f"> {first_line}",
                    "",
                ]

    lines += [
        "---",
        "",
        "## Resultados de Echidna",
        "",
    ]

    if not echidna_rows:
        lines += [
            "> No se ejecutó Echidna o no se proporcionaron resultados.",
            "",
        ]
    else:
        lines += [
            "| Función | SWC | Detector | Testable | Resultado |",
            "|---------|-----|----------|----------|-----------|",
        ]
        for row in echidna_rows:
            testable = "Sí" if row["echidna_testable"] else "⚠ No"
            status = row["echidna_status"]
            if status == "passed":
                result = "✅ passed"
            elif status == "failed":
                result = "❌ failed"
            elif not row["echidna_testable"]:
                result = "⚠ no testable (ver advertencia)"
            else:
                result = f"— {status}"

            lines.append(
                f"| `{row['function']}` | {row['swc_id']} | {row['detector']} "
                f"| {testable} | {result} |"
            )

        lines += [""]

        non_testable = [r for r in echidna_rows if not r["echidna_testable"]]
        if non_testable:
            lines += [
                "### Advertencias — propiedades no testables automáticamente",
                "",
            ]
            # Deduplicar por (función, swc_id) para no repetir el mismo aviso
            seen = set()
            for r in non_testable:
                key = (r["function"], r["swc_id"])
                if key in seen:
                    continue
                seen.add(key)
                lines += [
                    f"**`{r['function']}()` — {r['swc_id']}**",
                    "",
                    f"> {r.get('warning', 'Requiere contrato atacante externo.')}",
                    "",
                    "> La propiedad Echidna se ha incluido en el wrapper como documentación",
                    "> del invariante esperado, pero un resultado *passed* no descarta la",
                    "> vulnerabilidad real. Se recomienda auditoría manual.",
                    "",
                ]

    lines += [
        "---",
        "",
        "## Recomendaciones",
        "",
    ]

    if summary["total_findings"] == 0:
        lines += ["> No se detectaron vulnerabilidades. El contrato parece seguro.", ""]
    else:
        high_findings = [f for f in findings if f.get("severity") == "high"]
        if high_findings:
            lines += ["### Alta prioridad — resolver antes del despliegue", ""]
            for f in high_findings:
                lines.append(f"- **`{f.get('function')}()`** ({f.get('swc_id')}): {f.get('vuln_type', '')}")
            lines += [""]

        medium_findings = [f for f in findings if f.get("severity") == "medium"]
        if medium_findings:
            lines += ["### Media prioridad — revisar en el siguiente ciclo", ""]
            for f in medium_findings:
                lines.append(f"- **`{f.get('function')}()`** ({f.get('swc_id')}): {f.get('vuln_type', '')}")
            lines += [""]

        if summary["echidna_non_testable"]:
            lines += [
                "### Auditoría manual recomendada",
                "",
                f"- {summary['echidna_non_testable']} vulnerabilidad(es) no pueden verificarse",
                "  automáticamente con Echidna. Se requiere revisión manual o fuzzing con",
                "  contrato atacante personalizado.",
                "",
            ]

    lines += [
        "---",
        "",
        "*Informe generado automáticamente por evmaudit — TFM UNIR 2025*",
    ]

    return "\n".join(lines)


def generate_report(
    contract_path: str,
    correlator_output: dict,
    echidna_output: dict = None,
    adapter_meta: dict = None,
) -> dict:
    """
    Punto de entrada del reporter.

    Parámetros:
      contract_path     : ruta al .sol original analizado
      correlator_output : dict devuelto por correlate()
      echidna_output    : dict devuelto por run_echidna() (opcional)
      adapter_meta      : dict devuelto por echidna_adapter.generate() (opcional)

    Devuelve el dict con el informe completo y guarda en disco:
      - jsons/{contrato}/{contrato}_report.json
      - jsons/{contrato}/{contrato}_report.md
    """
    echidna_output = echidna_output or {}
    adapter_meta = adapter_meta or {
        "vulnerabilities": [],
        "testable_count": 0,
        "non_testable_count": 0,
    }

    report = _build_json_report(contract_path, correlator_output, echidna_output, adapter_meta)
    markdown = _build_markdown_report(report)

    contract_stem = Path(contract_path).stem
    out_dir = Path("jsons") / contract_stem
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{contract_stem}_report.json"
    md_path = out_dir / f"{contract_stem}_report.md"

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    md_path.write_text(markdown)

    print(f"\n  [OK] Informe JSON:     {json_path}")
    print(f"  [OK] Informe Markdown: {md_path}")
    print(f"  [→]  Riesgo global: {report['summary']['risk_score']}/10")

    return report
