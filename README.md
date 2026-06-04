# evmaudit

Biblioteca de Python para el análisis automatizado de contratos inteligentes Ethereum.

## Descripción

`evmaudit` es un pipeline de análisis de seguridad para contratos Solidity que combina múltiples herramientas de análisis estático y simbólico (Slither, Mythril y Echidna) para proporcionar una evaluación integral de vulnerabilidades. El proceso sigue estas etapas:

1. **Análisis estático y simbólico**: Ejecuta Slither y Mythril sobre el contrato original
2. **Normalización**: Convierte las salidas de ambas herramientas a un formato común
3. **Correlación**: Identifica hallazgos detectados por ambas herramientas para aumentar la confianza
4. **Generación de wrappers Echidna**: Crea contratos Solidity wrapper con propiedades `echidna_*` para cada vulnerabilidad detectada
5. **Fuzzing con Echidna**: Ejecuta pruebas de fuzzing sobre los contratos wrapper generados
6. **Generación de informes**: Produce informes estructurados (JSON) y legibles (Markdown) con los resultados

El pipeline implementa la "Opción B" para vulnerabilidades no testables automáticamente por Echidna (como la reentrancia), incluyendo las propiedades en el wrapper con advertencias explícitas para documentar los invariantes esperados y guiar la auditoría manual.

## Características principales

- Integración de Slither, Mythril y Echidna en un único pipeline
- Normalización de salidas a formato común para facilitar la correlación
- Sistema de confianza basado en coincidencias entre herramientas
- Generación automática de wrappers Echidna con plantillas predefinidas
- Soporte para la Opción B en vulnerabilidades no testables
- Informes detallados en formato JSON y Markdown
- Gestión automática de entornos y versiones de Solidity
- Workarounds para bugs conocidos de Echidna 2.3.2

## Estructura del proyecto

```
evmaudit/
├── src/
│   └── evmaudit/                 # Código fuente de la biblioteca
│       ├── runner.py             # Ejecución de herramientas externas
│       ├── normalizer.py         # Normalización de salidas
│       ├── correlator.py         # Correlación de hallazgos
│       ├── swc_catalog.py        # Catálogo de plantillas Echidna
│       ├── echidna_adapter.py    # Generación de wrappers
│       ├── reporter.py           # Generación de informes
│       ├── exceptions.py         # Excepciones personalizadas
│       ├── models.py             # Modelos de datos
│       └── main.py               # Entrada principal
├── docs/                         # Documentación detallada por módulo
├── tests/                        # Tests unitarios
└── README.md                     # Este archivo
```

## Desarrollado por

Esta biblioteca fue desarrollada como parte del Trabajo Fin de Máster (TFM) en la Universidad Internacional de La Rioja (UNIR).

**Autores**:

- Daniel Rovira Martínez
- Paula Suárez Prieto
- Adrián Moreno Martín

**Institución**: UNIR - Universidad Internacional de La Rioja  
**Programa**: Máster en Tecnologías Blockchain y Criptoactivos  
**Año**: 2025-2026

## Uso básico

```python
from evmaudit import (
    run_slither, run_mythril,
    normalize_slither_output, normalize_mythril_output,
    correlate,
    generate_echidna_wrapper, run_echidna,
    generate_report
)

CONTRACT = "contracts/MiContrato.sol"
CONTRACT_NAME = "MiContrato"

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

## Requisitos

- Python 3.8+
- Slither, Mythril y Echidna instalados y disponibles en PATH
- solc-select para gestión de versiones de Solidity
- Dependencias de Python especificadas en pyproject.toml o requirements.txt

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.
