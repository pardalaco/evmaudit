import subprocess
import json
from typing import Dict, Any
from evmaudit.exceptions import ToolNotFoundError, AnalysisError

def run_mythril(contract_path: str, timeout: int = 120, depth: int = 22) -> Dict[str, Any]:
    """
    Ejecuta Mythril en modo de análisis de seguridad sobre el contrato especificado.
    
    Captura la salida JSON nativa y gestiona escenarios de timeout o errores
    de ejecución/compilación.
    """
    # Construcción del comando tal como lo requiere Mythril por CLI para salida JSON
    command = [
        "myth", "analyze",
        contract_path,
        # "--solc-args", "--optimize",  # Opcional pero recomendado para evitar fallos de tamaño
        "-o", "json",
        "--execution-timeout", str(timeout),
        "--max-depth", str(depth)
    ]
    
    try:
        # Ejecutamos el subproceso. 
        # Mythril suele devolver código 0 si no hay errores graves, pero usamos check=False
        # porque los hallazgos o ciertos warnings pueden cambiar el returncode.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 5 # Margen de gracia por si el timeout interno de Mythril se cuelga
        )
        
        # Si el contrato no compila o Mythril rompe por otra causa (ej. falta solc)
        if result.returncode != 0 and not result.stdout:
            raise AnalysisError(f"Mythril falló con código {result.returncode}: {result.stderr}")
            
        # Parseamos la salida cruda de Mythril
        raw_output = json.loads(result.stdout) if result.stdout.strip() else {}
        
        # Determinar si terminó por timeout. Mythril suele avisar en su salida,
        # o podemos inferirlo si se alcanzó el límite de tiempo aproximado.
        # Una forma común en Mythril es evaluar si el status es parcial o si stderr tiene warnings.
        status = "complete"
        if "timeout" in result.stderr.lower():
            status = "timeout"

        return raw_output

    except subprocess.TimeoutExpired:
        # El subproceso de Python mató a Mythril porque superó el tiempo físico
        raise AnalysisError(f"Mythril excedió el tiempo límite de ejecución de {timeout} segundos y fue terminado.")
        
    except FileNotFoundError:
        # Si 'myth' no está instalado en el PATH del sistema operativo
        raise ToolNotFoundError("La herramienta 'myth' (Mythril) no está instalada o no se encuentra en el PATH.")
        
    except json.JSONDecodeError:
        # En caso de que la salida de stdout no sea un JSON válido debido a un crash intermedio
        raise AnalysisError(f"No se pudo parsear la salida de Mythril. Stderr: {result.stderr}")