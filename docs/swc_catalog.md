# Módulo swc_catalog.py

Este módulo contiene el catálogo de plantillas Echidna organizadas por detector de Slither, utilizado por el adapter para generar automáticamente contratos wrapper con propiedades `echidna_*` para cada vulnerabilidad detectada.

## Estructura de cada entrada del catálogo

Cada entrada contiene los siguientes campos:

| Campo | Descripción |
|-------|-------------|
| `swc` | Código SWC correspondiente (ej: "SWC-107") |
| `titulo` | Nombre oficial de la vulnerabilidad |
| `impacto` | Severidad típica que Slither asigna |
| `modo` | Modo de Echidna recomendado (`property` o `assertion`) |
| `plantilla` | Código Solidity de la propiedad `echidna_*` (con `{func}` como placeholder) |
| `limitacion` | Qué casos no puede cubrir esta plantilla automática |
| `echidna_testable` | `True` si Echidna puede verificarla sin contrato atacante adicional |

## Funcionalidades principales

### `CATALOG`
Diccionario principal que mapea nombres de detectores de Slither a sus entradas de catálogo correspondientes.
Incluye 22 entradas que cubren las principales vulnerabilidades detectables por Slither con soporte Echidna.

### `MYTHRIL_TO_DETECTOR`
Tabla de traducción que mapea IDs SWC de Mythril (formato numérico) a listas de detectores de Slither correspondientes.
Permite que el adapter use el mismo catálogo para los outputs de ambas herramientas.

### Funciones

#### `get_template(detector_name: str) -> dict | None`
Devuelve la entrada del catálogo para un detector de Slither dado.
Retorna `None` si el detector no está en el catálogo.

#### `get_template_from_swc(swc_id: str) -> list[dict]`
Devuelve las entradas del catálogo correspondientes a un SWC dado.
Acepta tanto el formato `"SWC-107"` como `"107"` para compatibilidad.
Un mismo SWC puede tener múltiples entradas si hay varios detectores de Slither que lo cubren (ej: SWC-107 tiene 4 detectores).

#### `detector_from_swc(swc_id: str) -> list[str]`
Devuelve los nombres de detector de Slither para un SWC dado.
Acepta tanto `"SWC-107"` como `"107"`.

#### `list_supported_detectors() -> list[str]`
Lista todos los detectores de Slither soportados por el catálogo.

## Características importantes

### Vulnerabilidades no testables automáticamente
Algunas vulnerabilidades como la reentrancia (SWC-107) tienen `echidna_testable = False` porque verificar su explotación requiere un contrato atacante externo que re-entre en el callback durante la ejecución.
El adapter sigue generando las propiedades en el wrapper pero las marca como no testables, lo que permite:
1. Documentar el invariante esperado aunque Echidna no pueda verificarlo automáticamente
2. Indicar explícitamente al auditor qué vulnerabilidades requieren revisión manual

### Limitaciones documentadas
Cada entrada incluye un campo `limitacion` que describe explícitamente qué casos no puede cubrir la plantilla automática, ayudando a los auditores a comprender el alcance de las verificaciones automáticas.

## Integración con el pipeline

Este módulo es utilizado por:
1. `echidna_adapter.py`: Para generar los wrappers Echidna con las propiedades adecuadas
2. El proceso de correlación: Para traducir entre SWC y detectores de Slither

El catálogo permite que el pipeline sea extensible: para añadir soporte para nuevas vulnerabilidades, basta con añadir una nueva entrada al `CATALOG` y actualizar las tablas de traducción si es necesario.