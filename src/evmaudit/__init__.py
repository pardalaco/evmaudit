from evmaudit.runner import run_mythril
from evmaudit.exceptions import ToolNotFoundError, AnalysisError

__all__ = ["run_mythril", "ToolNotFoundError", "AnalysisError"]

def hello() -> str:
    return "Hello from evmaudit!"
