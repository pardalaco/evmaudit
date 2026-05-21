class EVMAuditError(Exception):
    """Excepción base para todos los errores del paquete evmaudit."""
    pass

class ToolNotFoundError(EVMAuditError):
    """Se lanza cuando una herramienta externa (como Mythril o Slither) no está instalada."""
    pass

class AnalysisError(EVMAuditError):
    """Se lanza cuando la herramienta externa falla críticamente (ej. errores de compilación)."""
    pass