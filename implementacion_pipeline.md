# Implementación del pipeline de análisis — `evmaudit`

## Descripción general

Este documento describe la implementación de los módulos del pipeline de análisis automatizado de la librería `evmaudit`, que lleva el proceso desde la salida cruda de las herramientas de análisis hasta la generación de un informe final estructurado.

El pipeline completo tiene la siguiente forma:

```
contracts/Contrato.sol
        │
        ▼
┌───────────────────────────────────────┐
│  run_slither()  /  run_mythril()      │
└────────┬──────────────────────────────┘
         │  salida cruda JSON de cada herramienta
         ▼
┌───────────────────────────────────────┐
│  normalize_slither_output()           │
│  normalize_mythril_output()           │
└────────────────┬──────────────────────┘
                 │  formato común: {tool, findings[{swc_id, severity, function...}]}
                 ▼
┌───────────────────────────────────────┐
│  correlate()                          │
└────────────────┬──────────────────────┘
                 │  findings agrupados por (contrato, función, SWC)
                 ▼
┌───────────────────────────────────────┐
│  generate() — echidna_adapter         │
│  (usa swc_catalog para plantillas)    │
└────────────────┬──────────────────────┘
                 │  wrapper .sol con propiedades echidna_*
                 ▼
┌───────────────────────────────────────┐
│  run_echidna()                        │
└────────────────┬──────────────────────┘
                 │  resultados del fuzzing por propiedad
                 ▼
┌───────────────────────────────────────┐
│  generate_report()                    │
└────────────────┬──────────────────────┘
                 │
                 ▼
  jsons/{contrato}/{contrato}_report.json
  jsons/{contrato}/{contrato}_report.md
```

---

## Módulos implementados

### 1. `runner.py`

#### `run_slither(contract_path, timeout) → dict`

Ejecuta Slither sobre el archivo Solidity indicado invocándolo como subproceso con la opción `--json -`, que vuelca la salida estructurada por la salida estándar. Verifica previamente que Slither está instalado (`slither --version`) y lanza `ToolNotFoundError` si no se encuentra. Slither devuelve el código de retorno `255` cuando encuentra hallazgos — esto no es un error, por lo que la función considera `success=True` tanto para código `0` como `255`. Guarda el resultado crudo en `jsons/{contrato}/{contrato}_slither.json`.

#### `run_mythril(contract_path, timeout, depth) → dict`

Ejecuta Mythril en modo `analyze` sobre el contrato. Los parámetros `timeout` (segundos) y `depth` (profundidad máxima del grafo de estados) permiten controlar el balance entre cobertura y tiempo de análisis. El valor por defecto `depth=22` es el recomendado por la documentación oficial para contratos de complejidad media. Si Mythril no devuelve salida JSON válida, lanza `AnalysisError`. Guarda el resultado crudo en `jsons/{contrato}/{contrato}_mythril.json`.

#### `_env() → dict`

**Problema que resuelve:** cuando Python ejecuta herramientas externas (`slither`, `myth`, `echidna`) como subprocesos, el proceso hijo hereda el `PATH` del proceso padre pero no tiene acceso al entorno activado del entorno virtual. Esto hace que `solc` (compilador de Solidity, instalado dentro del venv) no sea encontrado, y tanto Slither como Mythril fallan con `FileNotFoundError`.

**Solución:** `_env()` construye un diccionario de entorno añadiendo `{venv}/bin` al inicio del `PATH` antes de pasárselo a cada subproceso.

```python
def _env() -> dict:
    env = os.environ.copy()
    venv_bin = str(Path(sys.prefix) / "bin")
    env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
    return env
```

Todas las llamadas a `subprocess.run()` en el módulo reciben `env=_env()`.

#### `_save_json(data, contract_path, tool) → Path`

Guarda el JSON de salida de cada herramienta en una carpeta específica del contrato. La estructura de carpetas es:

```
jsons/
└── {nombre_contrato}/
    ├── {contrato}_slither.json
    ├── {contrato}_mythril.json
    ├── {contrato}_echidna.json
    ├── {contrato}_slither_normalizado.json
    ├── {contrato}_mythril_normalizado.json
    ├── {contrato}_correlacionado.json
    ├── {contrato}_adapter.json
    ├── {contrato}_report.json
    └── {contrato}_report.md
```

Esta estructura garantiza que todos los artefactos de un mismo análisis queden agrupados en una carpeta con el nombre del contrato, facilitando la trazabilidad y la reproducción del análisis.

#### `run_echidna(contract_path, contract_name, config_path, output_contract_path) → dict`

Ejecuta Echidna sobre el contrato wrapper generado por el adapter. Además de la invocación básica, esta función incorpora tres correcciones para bugs conocidos de Echidna 2.3.2:

**Bug 1 — nombres de test (`_fix_echidna_names`):** en la salida JSON de Echidna 2.3.2, el campo `name` de cada test aparece como la cadena literal `"name"` en lugar del nombre real de la función `echidna_*`. La corrección lee el archivo `.sol` del wrapper, extrae los nombres de las funciones `echidna_*` mediante expresión regular y los asigna por posición a los tests del JSON:

```python
echidna_funcs = re.findall(r'function (echidna_\w+)\s*\(', sol_code)
for i, test in enumerate(tests):
    if i < len(echidna_funcs):
        test["name"] = echidna_funcs[i]
```

**Bug 2 — status "fuzzing" (`_fix_echidna_status`):** el campo `status` de cada test permanece como `"fuzzing"` en el JSON aunque la campaña haya terminado. Cuando Echidna opera en modo `--format json` no vuelca los resultados en texto plano, por lo que este workaround busca los patrones `"echidna_X: passed!"` y `"echidna_X: failed!"` en las líneas no-JSON de la salida estándar y actualiza el campo `status` en consecuencia.

**Bug 3 — status "shrinking":** cuando Echidna encuentra una violación de una propiedad, la marca como `"shrinking"` mientras reduce el contraejemplo al mínimo caso que lo reproduce. Si el proceso termina mientras está en esta fase, el JSON queda congelado con ese valor. Dado que `"shrinking"` solo ocurre cuando ya se ha encontrado un fallo, la corrección lo traduce directamente a `"failed"`:

```python
elif test.get("status") == "shrinking":
    test["status"] = "failed"
    test["passed"] = False
```

El parámetro `output_contract_path` indica la ruta del contrato original para que el JSON de resultados se guarde en la carpeta del análisis correspondiente (`jsons/{contrato}/`) y no en una subcarpeta del wrapper.

#### `run_all(contract_path) → dict`

Orquestador que ejecuta Slither y Mythril secuencialmente y devuelve los dos resultados crudos. Echidna no se incluye aquí porque entra más adelante en el pipeline, tras el correlator y el adapter, sobre un contrato wrapper distinto al original.

---

### 2. `normalizer.py` — Normalización de salidas

Este módulo convierte la salida cruda de cada herramienta al formato común que consume el correlator. El formato de salida es idéntico para Slither y Mythril:

```python
{
    "tool": "slither" | "mythril",
    "findings": [
        {
            "title":       str,   # nombre de la vulnerabilidad
            "description": str,   # descripción detallada
            "severity":    str,   # siempre en minúscula: "high", "medium", "low"...
            "category":    str,   # "economic" | "access_control" | "business_logic" | "execution"
            "contract":    str,   # nombre del contrato afectado
            "function":    str,   # nombre de la función (sin parámetros)
            "location":    dict,  # {"file": str, "line": int} o {"file": str, "lines": [int]}
            "swc_id":      str,   # "SWC-107", "SWC-106"...
            "raw":         dict,  # hallazgo original sin modificar
        }
    ]
}
```

#### `SLITHER_TO_SWC` — tabla de correspondencia

Slither identifica las vulnerabilidades por nombre de detector (ej. `"reentrancy-eth"`), no por SWC. Se implementa una tabla de 22 entradas que traduce cada detector al SWC correspondiente. Los detectores sin SWC asignado (como `"solc-version"` o `"low-level-calls"`) se descartan porque no representan vulnerabilidades explotables:

```python
SLITHER_TO_SWC = {
    "reentrancy-eth":          "SWC-107",
    "reentrancy-no-eth":       "SWC-107",
    "arbitrary-send-eth":      "SWC-105",
    "suicidal":                "SWC-106",
    "tx-origin":               "SWC-115",
    "timestamp":               "SWC-116",
    # ... 17 entradas más
}
```

#### `normalize_mythril_output(raw_output) → dict`

Mythril devuelve el SWC como número entero (`"107"`). Esta función lo formatea al estándar `"SWC-107"`. También elimina los parámetros del nombre de función (`"withdraw(uint256)"` → `"withdraw"`), ya que el correlator agrupa por nombre de función y necesita que coincida con el que devuelve Slither. Guarda el resultado en `jsons/{contrato}/{contrato}_mythril_normalizado.json`.

#### `normalize_slither_output(raw_output) → dict`

Slither organiza sus hallazgos en una lista de `detectors`, cada uno con una lista de `elements` (nodos del AST). Esta función extrae el nombre de la función afectada buscando en los `elements` el de tipo `"function"`, y el nombre del contrato buscando el campo `parent` de tipo `"contract"`. Los detectores sin SWC en la tabla `SLITHER_TO_SWC` se omiten. Guarda el resultado en `jsons/{contrato}/{contrato}_slither_normalizado.json`.

#### `_extract_function(detector) → str`

Helper privado. Recorre la lista de `elements` de un detector de Slither y devuelve el nombre del primer element de tipo `"function"` que encuentre. Si no hay ninguno, devuelve `"unknown"`.

#### `_extract_contract(detector) → str`

Helper privado. Busca el nombre del contrato afectado en el campo `parent` de los elements (que apunta al contrato contenedor) o directamente en elements de tipo `"contract"`.

#### `_extract_lines(detector) → list[int]`

Helper privado. Devuelve las líneas de código de la función afectada, sin duplicados y ordenadas. Solo extrae las líneas del element de tipo `"function"` para evitar repetir líneas de sub-expresiones internas.

#### `_infer_category_by_swc(swc_id, title) → str`

Clasifica el hallazgo en una de las cuatro categorías del estado del arte a partir del SWC:

| Categoría | SWCs |
|-----------|------|
| `access_control` | SWC-105, 106, 112, 115, 124, 130 |
| `economic` | SWC-107, 113, 114 |
| `business_logic` | SWC-131, 135 |
| `execution` | resto |

---

### 3. `correlator.py` — Correlación de hallazgos

Este módulo recibe los dos outputs normalizados y los cruza para detectar qué vulnerabilidades han sido detectadas por más de una herramienta.

#### Clave de agrupación

La agrupación se realiza por la tupla `(contrato, función, swc_id)`. Este criterio es más preciso que agrupar solo por tipo de vulnerabilidad porque dos funciones distintas del mismo contrato pueden tener el mismo tipo de vulnerabilidad y deben aparecer como hallazgos independientes.

#### `_extract_findings(normalized, tool) → list[dict]`

Convierte los findings del formato normalizado al formato interno del correlator. Homogeneiza la localización: Slither usa `location.lines` (lista de enteros) mientras que Mythril usa `location.line` (un único entero). Ambos se convierten siempre a lista.

#### `_extract_findings(normalized, tool) → list[dict]`

Convierte los findings del formato normalizado al formato interno del correlator añadiendo el nombre de la herramienta a cada finding. Homogeneiza la localización: Slither usa `location.lines` (lista) mientras que Mythril usa `location.line` (entero). Ambos se convierten siempre a lista para que el merge posterior pueda calcular la unión.

#### `_merge_findings(slither_findings, mythril_findings) → list[dict]`

Para cada grupo con la misma clave `(contrato, función, SWC)`:

- Si aparece en ambas herramientas: `status = "confirmed"`, `confidence_score = 3`
- Si aparece solo en una: `status = "detected"`, `confidence_score = 2`
- `severity` = la máxima entre las dos herramientas
- `lines` = unión ordenada de las líneas de ambas herramientas
- `evidence` = dict con las evidencias de cada herramienta

#### `correlate(slither_normalized, mythril_normalized, contract_path) → dict`

Punto de entrada del módulo. Devuelve y guarda en disco la estructura:

```python
{
    "contract": "VulnerableBank",
    "findings": [
        {
            "contract":         "VulnerableBank",
            "function":         "withdraw",
            "swc_id":           "SWC-107",
            "vuln_type":        "reentrancy",
            "severity":         "high",
            "confidence_score": 3,
            "status":           "confirmed",
            "lines":            [11, 12, 13, 14, 15, 16],
            "confirmed_by":     ["mythril", "slither"],
            "evidence": {
                "slither": { "title": "...", "description": "..." },
                "mythril": { "title": "...", "description": "..." }
            }
        }
    ]
}
```

---

### 4. `swc_catalog.py` — Catálogo de plantillas Echidna

Catálogo de 22 entradas, una por detector de Slither con soporte en el pipeline. Cada entrada contiene:

| Campo | Descripción |
|-------|-------------|
| `swc` | Código SWC correspondiente |
| `titulo` | Nombre oficial de la vulnerabilidad |
| `impacto` | Severidad típica que Slither asigna |
| `modo` | Modo de Echidna recomendado (`property` o `assertion`) |
| `plantilla` | Código Solidity de la propiedad `echidna_*` (con `{func}` como placeholder) |
| `limitacion` | Qué casos no puede cubrir esta plantilla automática |
| `echidna_testable` | `True` si Echidna puede verificarla sin contrato atacante adicional |

El campo `echidna_testable` es clave para la Opción B del adapter. Las vulnerabilidades de reentrancia (SWC-107) tienen `echidna_testable = False` porque verificar reentrancia requiere un contrato atacante externo que re-entre en el callback durante la ejecución — algo que Echidna no puede generar automáticamente.

#### `detector_from_swc(swc_id) → list[str]`

Traduce un SWC al conjunto de detectores de Slither que lo cubren. Acepta tanto el formato `"SWC-107"` como `"107"` para compatibilidad con la salida del correlator.

#### `get_template_from_swc(swc_id) → list[dict]`

Devuelve las entradas del catálogo correspondientes a un SWC dado. Una misma vulnerabilidad puede tener múltiples entradas si hay varios detectores de Slither que la cubren (por ejemplo, SWC-107 tiene cuatro detectores: `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign`, `reentrancy-unlimited-gas`).

---

### 5. `echidna_adapter.py` — Generador de wrappers Echidna

Este módulo recibe el output del correlator y genera automáticamente un contrato Solidity wrapper que hereda del contrato original e incorpora propiedades `echidna_*` para cada vulnerabilidad detectada.

#### Opción B para vulnerabilidades no testables

El pipeline implementa la **Opción B** para las vulnerabilidades marcadas con `echidna_testable = False`: en lugar de omitirlas, se incluye la propiedad en el wrapper pero con un bloque de advertencia visible en los comentarios del código generado. Esto tiene dos ventajas:

1. El wrapper documenta el invariante esperado aunque Echidna no pueda verificarlo automáticamente.
2. El reporter puede indicar explícitamente al auditor qué vulnerabilidades requieren revisión manual.

Un resultado `passed` de Echidna en una propiedad no testable **no descarta la vulnerabilidad** — simplemente confirma que el invariante se cumple sin un atacante externo, lo cual no es suficiente para descartar reentrancia.

#### `generate(correlator_output, contract_path, contract_name) → dict`

Punto de entrada del módulo. Para cada finding del correlator:

1. Traduce el `swc_id` a detectores de Slither mediante `detector_from_swc()`
2. Busca las plantillas en el catálogo para cada detector
3. Sustituye `{func}` por el nombre de la función vulnerable
4. Genera el wrapper `.sol` con todas las propiedades

Devuelve un diccionario con los metadatos del análisis:

```python
{
    "wrapper_path":          "jsons/VulnerableBank/VulnerableBank_Echidna.sol",
    "contract_name_echidna": "VulnerableBank_Echidna",
    "vulnerabilities": [
        {
            "swc_id":           "SWC-107",
            "function":         "withdraw",
            "detectors":        ["reentrancy-eth", "reentrancy-no-eth"],
            "confirmed_by":     ["mythril", "slither"],
            "echidna_testable": False,
            "warning":          "Requiere contrato atacante externo..."
        }
    ],
    "testable_count":     2,
    "non_testable_count": 1,
    "skipped_count":      0
}
```

También copia el contrato original a la carpeta del análisis para que el `import` del wrapper compile correctamente.

#### `_generate_wrapper(contract_path, contract_name, vulnerabilities) → str`

Helper privado. Genera el código Solidity del contrato wrapper como cadena de texto. Para cada vulnerabilidad itera sus detectores, obtiene la plantilla del catálogo y la formatea sustituyendo `{func}` por el nombre de la función. Las vulnerabilidades con `echidna_testable=False` reciben un bloque de comentario de advertencia antes de la propiedad.

#### `_save_wrapper(code, contract_path, contract_name) → Path`

Helper privado. Escribe el código Solidity generado en `jsons/{contrato}/{contract_name}_Echidna.sol` y devuelve la ruta del archivo creado.

#### `_save_metadata(metadata, contract_path, contract_name) → Path`

Helper privado. Guarda el dict de metadatos devuelto por `generate()` en `jsons/{contrato}/{contrato}_adapter.json` para que el reporter pueda leerlo sin necesidad de volver a ejecutar el adapter.

---

### 6. `reporter.py` — Generación del informe final

Este módulo genera el informe final del análisis combinando los resultados de las tres herramientas. Produce dos artefactos:

- `{contrato}_report.json` — datos estructurados para integración en otros sistemas
- `{contrato}_report.md` — informe legible en Markdown para el auditor

#### `generate_report(contract_path, correlator_output, echidna_output, adapter_meta) → dict`

Punto de entrada del módulo. Los parámetros `echidna_output` y `adapter_meta` son opcionales — si no se proporcionan, el informe se genera igualmente con los resultados de Slither y Mythril únicamente.

#### Puntuación de riesgo global (`_risk_score`)

Se calcula como suma ponderada de severidad × confidence_score, normalizada a 10:

```
risk_score = min(Σ(peso_severidad × confidence_score) / 9, 10)
```

Donde los pesos de severidad son: `high=10`, `medium=5`, `low=2`, `informational=0`.

La referencia de normalización (divisor 9) corresponde a 3 findings de severidad high con confidence 3: `3 × 10 × 3 / 9 = 10`. Un contrato con una única vulnerabilidad high confirmada obtiene `10 × 3 / 9 = 3.3`. Un contrato con dos high y un medium confirmados obtiene `(10+10+5) × 3 / 9 = 8.3`.

#### `_build_json_report(contract_path, correlator_output, echidna_output, adapter_meta) → dict`

Helper privado. Construye el diccionario completo del informe llamando a `_risk_score()` y `_echidna_summary()`. Este dict es lo que se serializa como JSON y lo que usa `_build_markdown_report()` para generar el Markdown.

#### `_build_markdown_report(report) → str`

Helper privado. Recibe el dict del informe y genera el documento Markdown completo como cadena de texto. Construye cada sección iterando los findings y los resultados de Echidna. Las propiedades no testables se deduplican por `(función, swc_id)` para que la misma advertencia no aparezca múltiples veces cuando varios detectores apuntan a la misma función.

#### `_risk_score(findings) → float`

Helper privado. Calcula la puntuación de riesgo global (0–10) como suma ponderada de severidad × confidence_score, normalizada a 10. Ver fórmula en la sección anterior.

#### Sección de resultados Echidna (`_echidna_summary`)

Cruza los resultados de Echidna con los metadatos del adapter para construir la tabla del informe. El cruce se realiza buscando el nombre de la función en los nombres de los tests (`"withdraw"` en `"echidna_withdraw_solvency"`). Para propiedades no testables, el resultado en el informe es `"⚠ no testable (ver advertencia)"` independientemente del status que devuelva Echidna.

#### Estructura del informe Markdown

```
# Informe de Análisis — {contrato}
## Resumen ejecutivo
   - Tabla con totales: hallazgos, confirmed/detected, alta severidad
   - Puntuación de riesgo [████████░░] 8.3/10
## Hallazgos correlacionados
   - Tabla: función | SWC | tipo | severidad | confianza | estado
## Detalle de hallazgos
   - Por cada finding: descripción, líneas, evidencia de cada herramienta
## Resultados de Echidna
   - Tabla: función | SWC | detector | testable | resultado
   - Advertencias para propiedades no testables (deduplicadas por función)
## Recomendaciones
   - Alta prioridad (high severity)
   - Media prioridad (medium severity)
   - Auditoría manual recomendada (si hay no-testables)
```

---

## Cómo ejecutar el pipeline completo

### Requisitos previos

```bash
# Desde el directorio raíz del workspace (TFM-UNIR/)
uv pip install -e evmaudit/     # instalar el paquete en modo editable
solc-select install 0.8.20      # compilador Solidity
solc-select use 0.8.20
```

### Ejecución paso a paso

```python
from evmaudit import (
    run_slither, run_mythril,
    normalize_slither_output, normalize_mythril_output,
    correlate,
    generate_echidna_wrapper, run_echidna,
    generate_report
)

CONTRACT = "contracts/MiContrato.sol"
CONTRACT_NAME = "MiContrato"   # nombre del contract en el .sol

# 1. Análisis estático y simbólico
slither_raw = run_slither(CONTRACT)
mythril_raw = run_mythril(CONTRACT, timeout=120)

# 2. Normalización al formato común
slither_norm = normalize_slither_output(slither_raw)
mythril_norm  = normalize_mythril_output(mythril_raw)

# 3. Correlación: agrupa por (contrato, función, SWC)
corr = correlate(slither_norm, mythril_norm, CONTRACT)

# 4. Generación del wrapper Echidna (Opción B para no-testables)
meta = generate_echidna_wrapper(corr, CONTRACT, CONTRACT_NAME)

# 5. Fuzzing con Echidna (solo si se generó wrapper)
echidna_out = {}
if meta["wrapper_path"]:
    echidna_out = run_echidna(
        meta["wrapper_path"],
        meta["contract_name_echidna"],
        output_contract_path=CONTRACT,
    )

# 6. Informe final
report = generate_report(CONTRACT, corr, echidna_out, meta)
print(f"Riesgo: {report['summary']['risk_score']}/10")
print(f"Informe: jsons/{CONTRACT_NAME}/{CONTRACT_NAME}_report.md")
```

### Artefactos generados

Tras la ejecución, la carpeta `jsons/{contrato}/` contiene:

| Archivo | Función | Contenido |
|---------|---------|-----------|
| `{c}_slither.json` | `run_slither()` | Salida cruda de Slither |
| `{c}_mythril.json` | `run_mythril()` | Salida cruda de Mythril |
| `{c}_slither_normalizado.json` | `normalize_slither_output()` | Findings normalizados |
| `{c}_mythril_normalizado.json` | `normalize_mythril_output()` | Findings normalizados |
| `{c}_correlacionado.json` | `correlate()` | Findings cruzados con scores |
| `{c}_adapter.json` | `generate_echidna_wrapper()` | Metadatos del wrapper |
| `{c}_Echidna.sol` | `generate_echidna_wrapper()` | Wrapper con propiedades echidna_* |
| `{c}.sol` | `generate_echidna_wrapper()` | Copia del contrato original (para import) |
| `{c}_echidna.json` | `run_echidna()` | Resultados del fuzzing |
| `{c}_report.json` | `generate_report()` | Informe estructurado completo |
| `{c}_report.md` | `generate_report()` | Informe Markdown para el auditor |

---

## Limitaciones conocidas

### Reentrancia (SWC-107) — no testable automáticamente

Verificar reentrancia con Echidna requiere un contrato atacante externo que re-entre en el callback durante la ejecución. El adapter genera las propiedades de solvencia correspondientes (e.g., `echidna_withdraw_solvency`) pero las marca como `echidna_testable=False`. Un resultado `passed` de Echidna en estas propiedades confirma que el invariante de solvencia se cumple sin un atacante — lo cual no descarta la vulnerabilidad real. Se recomienda auditoría manual para todos los hallazgos SWC-107.

### Bugs de Echidna 2.3.2

| Bug | Síntoma | Workaround implementado |
|-----|---------|------------------------|
| Nombres de test | `name: "name"` en lugar del nombre real | `_fix_echidna_names()`: extrae nombres del .sol por posición |
| Status "fuzzing" | Status no se actualiza al terminar | `_fix_echidna_status()`: busca patrones en stdout |
| Status "shrinking" | Status congelado al minimizar contraejemplo | Se traduce directamente a `"failed"` |

### Detección de tx.origin (SWC-115)

La propiedad `echidna_adminAction_no_txorigin_bypass` no puede verificar el bypass de `tx.origin` automáticamente porque Echidna siempre ejecuta transacciones con `msg.sender == tx.origin` (no simula el escenario de un contrato intermediario malicioso). El resultado habitual es `"fuzzing"` o `"passed"` sin que esto descarte la vulnerabilidad.
