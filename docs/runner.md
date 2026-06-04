# Módulo runner.py

Este módulo se encarga de ejecutar las herramientas de análisis estático y simbólico (Slither, Mythril y Echidna) sobre los contratos Solidity y gestionar su salida.

## Funciones

### `detect_contract_name(contract_path: str) -> str | None`
Lee el archivo Solidity y devuelve el nombre del primer contrato declarado. Evita el error de usar el nombre del archivo cuando el contrato se llama diferente (por ejemplo, `contratov1.sol` con `contract VulnerableBank`).

### `_set_solc_version(contract_path: str) -> str | None`
Detecta la versión de Solidity del pragma del contrato y configura `solc-select` para usarla antes de ejecutar cualquier herramienta de análisis. Soporta pragma con versiones exactas, mínimas y con caret.

### `_env() -> dict`
Devuelve el entorno del proceso con el `venv/bin` añadido al `PATH`. Necesario para que los subprocesos encuentren `solc`, `slither`, `myth` y `echidna` aunque se llame desde fuera del entorno activado.

### `_save_json(data: dict, contract_path: str, tool: str) -> Path`
Guarda el output de una herramienta en la carpeta del contrato siguiendo la estructura: `jsons/{contrato}/{contrato}_{tool}.json`. Crea el directorio si no existe.

### `run_mythril(contract_path: str, timeout: int = 120, depth: int = 22) -> Dict[str, Any]`
Ejecuta Mythril sobre el contrato y guarda la salida cruda en disco. Guarda el resultado en: `jsons/{contrato}/{contrato}_mythril.json`.

### `run_slither(contract_path: str, timeout: int = 60) -> dict`
Ejecuta Slither sobre el contrato y guarda la salida cruda en disco. Slither devuelve returncode 255 cuando encuentra hallazgos (no es un error), por eso consideramos success=True para returncode 0 y 255. Guarda el resultado en: `jsons/{contrato}/{contrato}_slither.json`.

### `run_echidna(contract_path: str, contract_name: str, config_path: str = None, output_contract_path: str = None) -> Dict[str, Any]`
Ejecuta Echidna sobre el contrato wrapper generado por el adapter y guarda el resultado. Este runner NO debe llamarse sobre contratos originales sin propiedades echidna_*. El flujo correcto es: Slither+Mythril → correlator → adapter → contrato wrapper → run_echidna(). Guarda el resultado en: `jsons/{contrato}/{contrato}_echidna.json`.

Incorpora workarounds para bugs conocidos de Echidna 2.3.2:
- `_fix_echidna_names()`: corrige el campo "name" de cada test que sale como "name" en lugar del nombre real.
- `_fix_echidna_status()`: corrige el status que queda como "fuzzing" y traduce "shrinking" a "failed".

### `run_all(contract_path: str) -> Dict[str, Any]`
Orquestador: ejecuta Slither y Mythril sobre el contrato y devuelve los dos outputs. Echidna no se incluye aquí porque entra más adelante en el pipeline, tras el correlator y el adapter. Guarda ambos resultados en: `jsons/{contrato}/`.