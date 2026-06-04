# Módulo echidna_adapter.py

Este módulo recibe el output del correlator y genera automáticamente un contrato Solidity wrapper que hereda del contrato original e incorpora propiedades `echidna_*` para cada vulnerabilidad detectada, listo para ser analizado con Echidna.

## Funcionalidad principal

Para cada finding correlacionado:
1. Traduce el `swc_id` al detector de Slither equivalente (via `swc_catalog`)
2. Obtiene la plantilla `echidna_*` correspondiente del catálogo
3. Sustituye `{func}` por el nombre de la función vulnerable
4. Genera un contrato wrapper que hereda del original con todas las propiedades

El wrapper se guarda en: `jsons/{contrato}/{contract_name}_Echidna.sol`
Y se ejecuta con: `run_echidna(wrapper_path, contract_name + "_Echidna")`

## Opción B para vulnerabilidades no testables

El pipeline implementa la **Opción B** para las vulnerabilidades marcadas con `echidna_testable = False`: en lugar de omitirlas, se incluye la propiedad en el wrapper pero con un bloque de advertencia visible en los comentarios del código generado. Esto tiene dos ventajas:

1. El wrapper documenta el invariante esperado aunque Echidna no pueda verificarlo automáticamente.
2. El reporter puede indicar explícitamente al auditor qué vulnerabilidades requieren revisión manual.

Un resultado `passed` de Echidna en una propiedad no testable **no descarta la vulnerabilidad** — simplemente confirma que el invariante se cumple sin un atacante externo, lo cual no es suficiente para descartar reentrancia.

## Funciones

### `_generate_wrapper(contract_path: str, contract_name: str, vulnerabilities: list[dict]) -> str`
Genera el código Solidity del contrato wrapper con todas las propiedades `echidna_*`.

Las propiedades de vulnerabilidades no testables se incluyen igual pero con un bloque de advertencia visible en el `.sol` para que quien lo lea sepa que Echidna no puede verificar ciertas vulnerabilidades sin un contrato atacante externo.

### `_save_wrapper(code: str, contract_path: str, contract_name: str) -> Path`
Guarda el wrapper `.sol` en la carpeta del contrato.

### `_save_metadata(metadata: dict, contract_path: str, contract_name: str) -> Path`
Guarda los metadatos del adapter (para el reporter) en disco.

### `generate(correlator_output: dict, contract_path: str, contract_name: str) -> dict`
Punto de entrada del adapter.

Recibe el output del correlator y genera el contrato wrapper para Echidna.

**Parámetros:**
- `correlator_output`: dict devuelto por `correlate()`
- `contract_path`: ruta al `.sol` original (para el import del wrapper)
- `contract_name`: nombre del contrato Solidity (ej: "VulnerableBank")

**Devuelve un dict con:**
```json
{
  "wrapper_path": "jsons/VulnerableBank/VulnerableBank_Echidna.sol",  // ruta al .sol generado
  "contract_name_echidna": "VulnerableBank_Echidna",                  // nombre del contrato wrapper
  "vulnerabilities": [
    {
      "swc_id": "SWC-107",
      "function": "withdraw",
      "detectors": ["reentrancy-eth", "reentrancy-no-eth"],
      "confirmed_by": ["mythril", "slither"],
      "echidna_testable": false,                                      // False → propiedad incluida con advertencia
      "warning": "Requiere contrato atacante externo..."              // descripción de la limitación si no testable
    }
  ],
  "testable_count": 2,                                               // número de vulnerabilidades testables
  "non_testable_count": 1,                                           // número de vulnerabilidades no testables
  "skipped_count": 0                                                 // SWC sin soporte en el catálogo
}
```

Las vulnerabilidades sin plantilla en el catálogo se omiten (skipped).
Las no testables se incluyen en el wrapper con advertencia (Opción B).

El módulo también copia el contrato original a la carpeta del análisis para que el `import` del wrapper compile correctamente.