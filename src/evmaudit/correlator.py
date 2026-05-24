#!/usr/bin/env python3
import json
from pathlib import Path
from collections import defaultdict


SLITHER_TO_SWC = {
    "reentrancy-eth": "SWC-107",
    "arbitrary-send-eth": "SWC-105",
    "unchecked-transfer": "SWC-104",
    "tx-origin": "SWC-115",
    "incorrect-equality": "SWC-132",
    "uninitialized-state": "SWC-109",
    "shadowing-state": "SWC-119",
    "suicidal": "SWC-106",
}


SLITHER_TO_VULN = {
    "reentrancy-eth": "reentrancy",
    "arbitrary-send-eth": "access_control",
    "unchecked-transfer": "unchecked_call",
    "tx-origin": "tx_origin_authentication",
    "incorrect-equality": "incorrect_equality",
    "uninitialized-state": "uninitialized_state",
    "shadowing-state": "state_variable_shadowing",
    "suicidal": "unprotected_selfdestruct",
}


MYTHRIL_SWC_TO_VULN = {
    "SWC-101": "integer_arithmetic",
    "SWC-105": "access_control",
    "SWC-107": "reentrancy",
    "SWC-110": "assert_violation",
    "SWC-115": "tx_origin_authentication",
}


SEVERITY_ORDER = {
    "informational": 0,
    "optimization": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


def normalize_severity(value: str) -> str:
    if not value:
        return "informational"
    return value.lower()


def confidence_from_tools(tools: list[str]) -> int:
    if len(set(tools)) >= 2:
        return 3
    return 2


def extract_lines_from_slither(elements: list[dict]) -> list[int]:
    lines = []

    for element in elements or []:
        source_mapping = element.get("source_mapping", {})
        for line in source_mapping.get("lines", []) or []:
            if isinstance(line, int):
                lines.append(line)

    return sorted(set(lines))


def extract_contract_name_from_slither(detector: dict, fallback: str) -> str:
    elements = detector.get("elements", [])

    for element in elements:
        name = element.get("name")
        type_ = element.get("type")

        if type_ == "contract" and name:
            return name

    first_markdown = detector.get("markdown", "")
    if "." in first_markdown:
        return first_markdown.split(".")[0].split()[-1]

    return fallback


def parse_slither_file(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))

    raw = data.get("raw", data)
    detectors = raw.get("results", {}).get("detectors", [])

    findings = []

    for detector in detectors:
        check = detector.get("check")
        impact = detector.get("impact", "Informational")

        swc_id = SLITHER_TO_SWC.get(check)
        vuln_type = SLITHER_TO_VULN.get(check, check)

        if not swc_id:
            continue

        contract_name = extract_contract_name_from_slither(detector, path.stem.replace("_slither", ""))
        lines = extract_lines_from_slither(detector.get("elements", []))

        findings.append({
            "contract": contract_name,
            "swc_id": swc_id,
            "vuln_type": vuln_type,
            "severity": normalize_severity(impact),
            "lines": lines,
            "tool": "slither",
            "evidence": {
                "slither": {
                    "check": check,
                    "impact": impact,
                    "description": detector.get("description", "").strip(),
                    "elements": detector.get("elements", []),
                }
            }
        })

    return findings


def parse_mythril_file(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))

    raw = data.get("raw", data)

    issues = []

    if isinstance(raw, dict):
        issues = raw.get("issues", [])

    findings = []

    for issue in issues:
        swc_id = issue.get("swc-id") or issue.get("swc_id")
        vuln_type = MYTHRIL_SWC_TO_VULN.get(swc_id, issue.get("title", "unknown").lower().replace(" ", "_"))

        lineno = issue.get("lineno")
        lines = [lineno] if isinstance(lineno, int) else []

        findings.append({
            "contract": path.stem.replace("_mythril", ""),
            "swc_id": swc_id,
            "vuln_type": vuln_type,
            "severity": normalize_severity(issue.get("severity", "medium")),
            "lines": lines,
            "tool": "mythril",
            "evidence": {
                "mythril": {
                    "title": issue.get("title"),
                    "lineno": lineno,
                    "description": issue.get("description"),
                    "function": issue.get("function"),
                    "tx_sequence": issue.get("tx_sequence") or issue.get("transaction_sequence"),
                }
            }
        })

    return findings


def merge_findings(slither_findings: list[dict], mythril_findings: list[dict]) -> dict:
    grouped = defaultdict(list)

    for finding in slither_findings + mythril_findings:
        key = (
            finding["contract"],
            finding["swc_id"],
            finding["vuln_type"],
        )
        grouped[key].append(finding)

    contracts = defaultdict(list)

    for (contract, swc_id, vuln_type), items in grouped.items():
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

        evidence = {}

        for item in items:
            evidence.update(item.get("evidence", {}))

        status = "confirmed" if len(tools) >= 2 else "detected"

        contracts[contract].append({
            "swc_id": swc_id,
            "vuln_type": vuln_type,
            "severity": severity,
            "confidence_score": confidence_from_tools(tools),
            "status": status,
            "lines": lines,
            "confirmed_by": tools,
            "evidence": evidence,
        })

    return {
        contract: {
            "contract": contract,
            "findings": findings,
        }
        for contract, findings in contracts.items()
    }


def process_results(
    slither_dir: str = "jsons/slither",
    mythril_dir: str = "jsons/mythril",
    output_dir: str = "jsons/final",
):
    path_slither = Path(slither_dir)
    path_mythril = Path(mythril_dir)
    path_output = Path(output_dir)

    path_output.mkdir(parents=True, exist_ok=True)

    slither_findings = []
    mythril_findings = []

    if path_slither.exists():
        for file in path_slither.glob("*_slither.json"):
            slither_findings.extend(parse_slither_file(file))

    if path_mythril.exists():
        for file in path_mythril.glob("*_mythril.json"):
            mythril_findings.extend(parse_mythril_file(file))

    merged = merge_findings(slither_findings, mythril_findings)

    for contract, report in merged.items():
        output_file = path_output / f"{contract}_final.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(f"[+] Generado: {output_file}")


if __name__ == "__main__":
    process_results()