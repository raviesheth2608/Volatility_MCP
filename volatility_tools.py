import subprocess
from pathlib import Path

VOL_PATH = r"C:\volatility-mcp\venv\Scripts\vol.exe"

def run_volatility(memory_path: str, plugin: str, extra_args=None):
    if extra_args is None:
        extra_args = []

    memory_path = Path(memory_path)

    if not memory_path.exists():
        return f"ERROR: Memory dump not found: {memory_path}"

    cmd = [
        VOL_PATH,
        "-f", str(memory_path),
        plugin
    ] + extra_args

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800  # 30 minutes
        )
    except subprocess.TimeoutExpired:
        return "ERROR: Volatility execution timed out (30 minutes)"

    # If Volatility exits non-zero, show stderr
    if result.returncode != 0:
        return f"ERROR:\n{result.stderr.strip()}"

    # Some plugins output warnings/info to stderr even on success
    output = result.stdout.strip()
    if not output and result.stderr.strip():
        return result.stderr.strip()

    return output or "Completed, but no output returned"
