# Módulo exceptions.py

Este módulo define las excepciones personalizadas utilizadas por la biblioteca evmaudit para manejar errores de manera específica y proporcionar información clara sobre los fallos durante el análisis.

## Excepciones

### `EVMAuditError(Exception)`
Excepción base para todos los errores del paquete evmaudit.
Todas las excepciones específicas del paquete heredan de esta clase.

### `ToolNotFoundError(EVMAuditError)`
Se lanza cuando una herramienta externa requerida (como Mythril, Slither o Echidna) no está instalada o no se encuentra en el PATH del sistema.

Esta excepción se utiliza en:
- `runner.py`: Cuando se verifica la disponibilidad de Slither o Mythril antes de ejecutarlos
- `run_echidna()`: Cuando se verifica la disponibilidad de Echidna

### `AnalysisError(EVMAuditError)`
Se lanza cuando la herramienta externa falla críticamente durante su ejecución, como por ejemplo:
- Errores de compilación de Solidity
- Tiempo de espera agotado (timeout)
- Errores internos de la herramienta que impiden obtener resultados útiles

Esta excepción se utiliza en:
- `runner.py`: Cuando las herramientas devuelven códigos de error inesperados o no producen salida
- `run_slither()`: Cuando Slither no devuelve JSON válido o excede el tiempo límite
- `run_mythril()`: Cuando Mythril falla críticamente o no produce salida JSON
- `run_echidna()`: Cuando Echidna falla críticamente o no produce salida JSON

## Uso típico

Estas excepciones permiten al llamador del pipeline capturar errores específicos y responder adecuadamente:

```python
from evmaudit.exceptions import ToolNotFoundError, AnalysisError
from evmaudit import run_slither

try:
    result = run_slither("contracts/MiContrato.sol")
except ToolNotFoundError:
    print("Error: Slither no está instalado. Instálalo con: pip install slither-analyzer")
except AnalysisError as e:
    print(f"Error durante el análisis: {e}")
```