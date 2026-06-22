import os
import re
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, Any
from evmaudit.exceptions import ToolNotFoundError, AnalysisError


def detect_contract_name(contract_path: str) -> str | None:
    """
    Lee el .sol y devuelve el nombre del primer contrato declarado.
    Evita el bug de usar el nombre del archivo cuando el contrato
    se llama diferente (ej: contratov1.sol con 'contract VulnerableBank').
    """
    try:
        code = Path(contract_path).read_text()
    except FileNotFoundError:
        return None
    matches = re.findall(r'^(?:abstract\s+)?contract\s+(\w+)', code, re.MULTILINE)
    return matches[0] if matches else Path(contract_path).stem


def _set_solc_version(contract_path: str) -> str | None:
    """
    Detecta la versión de Solidity del pragma del contrato y configura
    solc-select para usarla antes de ejecutar cualquier herramienta de análisis.

    Soporta:
      pragma solidity ^0.8.0;       → usa 0.8.0
      pragma solidity >=0.7.0;      → usa 0.7.0 (versión mínima del rango)
      pragma solidity 0.8.20;       → usa 0.8.20 (versión exacta)

    Devuelve la versión instalada, o None si no se encuentra pragma.
    """
    try:
        code = Path(contract_path).read_text()
    except FileNotFoundError:
        return None

    match = re.search(r'pragma solidity\s+[\^>=<~]*(\d+\.\d+\.\d+)', code)
    if not match:
        return None

    version = match.group(1)

    try:
        subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, env=_env()
        )
        subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, check=True, env=_env()
        )
        print(f"  [solc] versión configurada: {version}")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"  [solc] aviso: no se pudo configurar solc {version}, usando la versión actual")

    return version


def _env() -> dict:
    """
    Devuelve el entorno del proceso con el venv/bin añadido al PATH.
    Necesario para que los subprocesos encuentren solc, slither, myth y echidna
    aunque se llame desde fuera del entorno activado.
    """
    env = os.environ.copy()
    venv_bin = str(Path(sys.prefix) / "bin")
    env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
    return env


def _save_json(data: dict, contract_path: str, tool: str) -> Path:
    """
    Guarda el output de una herramienta en la carpeta del contrato.

    Estructura: jsons/{contrato}/{contrato}_{tool}.json
    Ejemplo: contracts/Reentrancy.sol + slither → jsons/Reentrancy/Reentrancy_slither.json

    Crea el directorio si no existe.
    """
    contract_stem = Path(contract_path).stem
    out_dir = Path("jsons") / contract_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{contract_stem}_{tool}.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return out_path


def run_mythril(
    contract_path: str,
    timeout: int = 120,
    depth: int = 22,
) -> Dict[str, Any]:
    """
    Ejecuta Mythril sobre el contrato y guarda la salida cruda en disco.

    Guarda el resultado en: jsons/{contrato}/{contrato}_mythril.json
    """
    _set_solc_version(contract_path)

    command = [
        "myth", "analyze",
        contract_path,
        "-o", "json",
        "--execution-timeout", str(timeout),
        "--max-depth", str(depth)
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 5,  # Margen de gracia por si el timeout interno de Mythril se cuelga
            env=_env(),
        )

        if result.returncode != 0 and not result.stdout:
            raise AnalysisError(f"Mythril falló con código {result.returncode}: {result.stderr}")

        raw_output = json.loads(result.stdout) if result.stdout.strip() else {}

        _save_json(raw_output, contract_path, "mythril")

        return raw_output

    except subprocess.TimeoutExpired:
        raise AnalysisError(f"Mythril excedió el tiempo límite de {timeout} segundos y fue terminado.")

    except FileNotFoundError:
        raise ToolNotFoundError("La herramienta 'myth' (Mythril) no está instalada o no se encuentra en el PATH.")

    except json.JSONDecodeError:
        raise AnalysisError(f"No se pudo parsear la salida de Mythril. Stderr: {result.stderr}")


def run_slither(
    contract_path: str,
    timeout: int = 60,
) -> dict:
    """
    Ejecuta Slither sobre el contrato y guarda la salida cruda en disco.

    Slither devuelve returncode 255 cuando encuentra hallazgos (no es un error),
    por eso consideramos success=True para returncode 0 y 255.

    Guarda el resultado en: jsons/{contrato}/{contrato}_slither.json
    """
    contract = Path(contract_path)

    if not contract.exists():
        raise AnalysisError(f"No existe el contrato: {contract_path}")

    _set_solc_version(contract_path)

    # Verificamos que Slither está instalado antes de intentar el análisis
    try:
        subprocess.run(
            ["slither", "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
            env=_env(),
        )
    except FileNotFoundError:
        raise ToolNotFoundError("Slither no está instalado o no está en el PATH.")
    except subprocess.SubprocessError as e:
        raise ToolNotFoundError(f"No se pudo ejecutar Slither: {e}")

    # --json - indica a Slither que vuelque el JSON por stdout
    cmd = ["slither", str(contract), "--json", "-"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_env())
    except subprocess.TimeoutExpired:
        raise AnalysisError(f"Slither excedió el tiempo límite de {timeout} segundos sobre {contract_path}")

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    if not stdout:
        raise AnalysisError(f"Slither no devolvió JSON. STDERR: {stderr}")

    try:
        raw_json = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise AnalysisError(f"No se pudo parsear JSON de Slither: {e}\nSTDERR: {stderr}")


    _save_json(raw_json, contract_path, "slither")

    return raw_json


def run_echidna(
    contract_path: str,
    contract_name: str,
    config_path: str = None,
    output_contract_path: str = None,
) -> Dict[str, Any]:
    """
    Ejecuta Echidna sobre el contrato wrapper generado por el adapter y guarda el resultado.

    Este runner NO debe llamarse sobre contratos originales sin propiedades echidna_*.
    El flujo correcto es: Slither+Mythril → correlator → adapter → contrato wrapper → run_echidna()

    output_contract_path: ruta del contrato original (para guardar el JSON en la carpeta
    correcta). Si no se indica, usa contract_path (el wrapper), lo que crea una subcarpeta
    separada con el nombre del wrapper.

    Guarda el resultado en: jsons/{contrato}/{contrato}_echidna.json
    """
    _set_solc_version(output_contract_path or contract_path)
    command = [
        "echidna",
        contract_path,
        "--contract", contract_name,
        "--format", "json"
    ]

    if config_path:
        command += ["--config", config_path]

    try:
        result = subprocess.run(command, capture_output=True, text=True, env=_env())

        # Echidna devuelve código distinto de 0 cuando encuentra propiedades violadas,
        # por lo que no fallamos por returncode. Solo fallamos si no hay salida alguna
        if result.returncode != 0 and not result.stdout:
            raise AnalysisError(f"Echidna falló con código {result.returncode}: {result.stderr}")

        # Echidna mezcla logs y JSON en stdout. Extraemos solo la línea que empieza por '{'
        stdout_lines = result.stdout.split('\n')
        json_lines = [l for l in stdout_lines if l.startswith('{')]
        raw_output = json.loads(json_lines[-1]) if json_lines else {}

        # Bug Echidna 2.3.2: el campo "name" de cada test sale como "name" en lugar
        # del nombre real de la propiedad echidna_*. Lo corregimos leyendo el .sol
        # y extrayendo los nombres de las funciones echidna_* por posición.
        raw_output = _fix_echidna_names(raw_output, contract_path)

        # El status en JSON puede quedar como "fuzzing". En modo --format json Echidna
        # mezcla el texto de resultados en stdout (junto al JSON), no en stderr.
        # Buscamos en las líneas no-JSON de stdout primero, y en stderr como fallback.
        non_json_stdout = '\n'.join(l for l in stdout_lines if not l.startswith('{'))
        raw_output = _fix_echidna_status(raw_output, non_json_stdout + '\n' + result.stderr)

        save_path = output_contract_path or contract_path
        _save_json(raw_output, save_path, "echidna")

        return raw_output

    except FileNotFoundError:
        raise ToolNotFoundError("La herramienta 'echidna' no está instalada o no se encuentra en el PATH.")

    except json.JSONDecodeError:
        raise AnalysisError(f"No se pudo parsear la salida de Echidna. Stderr: {result.stderr}")


def _fix_echidna_names(raw_output: dict, contract_path: str) -> dict:
    """
    Workaround bug Echidna 2.3.2: el campo 'name' de cada test sale como la
    cadena literal 'name' en lugar del nombre real de la propiedad echidna_*.

    Solución: extraemos los nombres de las funciones echidna_* del .sol por
    orden de aparición y los cruzamos con los tests por posición.
    """
    import re
    tests = raw_output.get("tests", [])
    if not tests:
        return raw_output

    try:
        sol_code = Path(contract_path).read_text()
        echidna_funcs = re.findall(r'function (echidna_\w+)\s*\(', sol_code)
        for i, test in enumerate(tests):
            if i < len(echidna_funcs):
                test["name"] = echidna_funcs[i]
    except Exception:
        pass  # Si falla, dejamos los nombres como están

    return raw_output


def _fix_echidna_status(raw_output: dict, stderr: str) -> dict:
    """
    Workaround bug Echidna 2.3.2: el status en JSON queda como 'fuzzing'
    en lugar de 'passed'/'failed'.

    Echidna sí reporta el resultado correcto en stderr en formato texto:
      'echidna_withdraw_solvency: failed!'
      'echidna_withdraw_state_consistent: passed!'

    Cruzamos esa información con los tests por nombre.
    """
    import re
    tests = raw_output.get("tests", [])
    if not tests:
        return raw_output

    # Extraer resultados del texto: "echidna_X: passed!" o "echidna_X: failed!"
    text_results = {}
    for match in re.finditer(r'(echidna_\w+):\s*(passed|failed)', stderr):
        text_results[match.group(1)] = match.group(2)

    for test in tests:
        name = test.get("name", "")
        if name in text_results:
            test["status"] = text_results[name]
            test["passed"] = text_results[name] == "passed"
        # "shrinking" significa que Echidna encontró una violación y está minimizando
        # el contraejemplo — equivale a "failed"
        elif test.get("status") == "shrinking":
            test["status"] = "failed"
            test["passed"] = False

    return raw_output


def run_all(contract_path: str) -> Dict[str, Any]:
    """
    Orquestador: ejecuta Slither y Mythril sobre el contrato y devuelve los dos outputs.

    Echidna no se incluye aquí porque entra más adelante en el pipeline,
    tras el correlator y el adapter.

    Guarda ambos resultados en: jsons/{contrato}/
    """
    slither_result = run_slither(contract_path)
    mythril_result = run_mythril(contract_path)

    return {
        "slither": slither_result,
        "mythril": mythril_result,
    }
