import argparse
from evmaudit.runner import run_slither, run_mythril, run_echidna, detect_contract_name
from evmaudit.normalizer import normalize_slither_output, normalize_mythril_output
from evmaudit.correlator import correlate
from evmaudit.echidna_adapter import generate as generate_echidna_wrapper
from evmaudit.reporter import generate_report

def main():
    parser = argparse.ArgumentParser(description="EVMAudit — Analizador automatizado de vulnerabilidades en contratos inteligentes.")
    parser.add_argument("contract_path", help="Ruta al archivo .sol del contrato inteligente")
    parser.add_argument("-n", "--name", help="Nombre del contrato (se detecta automáticamente si no se indica)")

    args = parser.parse_args()

    CONTRACT_PATH = args.contract_path

    # Detectar el nombre real del contrato desde el código fuente.
    # Evita errores cuando el archivo se llama diferente al contrato (ej: contratov1.sol).
    if args.name:
        CONTRACT_NAME = args.name
    else:
        CONTRACT_NAME = detect_contract_name(CONTRACT_PATH)

    print(f"\n{'='*50}")
    print(f"   Analizando: {CONTRACT_PATH}")
    print(f"{'='*50}\n")

    # PASO 1: Análisis estático + simbólico
    print("[1/5] Ejecutando Slither...")
    slither_raw = run_slither(CONTRACT_PATH)

    print("[2/5] Ejecutando Mythril (puede tardar 1-2 min)...")
    mythril_raw = run_mythril(CONTRACT_PATH, timeout=120, depth=22)

    # PASO 2: Normalización
    print("[3/5] Normalizando resultados...")
    slither_norm = normalize_slither_output(slither_raw)
    mythril_norm  = normalize_mythril_output(mythril_raw)

    # PASO 3: Correlación
    print("[4/5] Correlacionando hallazgos...")
    corr = correlate(slither_norm, mythril_norm, CONTRACT_PATH)
    print(f"      → {len(corr['findings'])} hallazgo(s) tras correlación")

    # PASO 4: Adapter + Echidna
    print("[5/5] Generando wrapper Echidna y ejecutando fuzzing...")
    adapter_meta = generate_echidna_wrapper(corr, CONTRACT_PATH, CONTRACT_NAME)

    echidna_raw = {}
    if adapter_meta["wrapper_path"]:
        echidna_raw = run_echidna(
            adapter_meta["wrapper_path"],
            adapter_meta["contract_name_echidna"],
            output_contract_path=CONTRACT_PATH,
        )

    # PASO 5: Informe final
    print("\n[OK] Generando informe...")
    report = generate_report(CONTRACT_PATH, corr, echidna_raw, adapter_meta)

    print(f"\n{'='*50}")
    print(f"   RESULTADO FINAL")
    print(f"   Risk score : {report['summary']['risk_score']}/10")
    print(f"   Hallazgos  : {report['summary']['total_findings']}")
    print(f"   Confirmados: {report['summary']['confirmed']}")
    print(f"{'='*50}")
    print(f"\n   Informe MD : jsons/{CONTRACT_NAME}/{CONTRACT_NAME}_report.md")

if __name__ == "__main__":
    main()