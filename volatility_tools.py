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

# Yara rule summarization function

def summarize_yara_results(output: str) -> str:
    lines = output.splitlines()

    rules = {}
    pids = set()
    regions = set()

    for line in lines:
        if "Rule:" in line:
            try:
                rule = line.split("Rule:")[1].split(",")[0].strip()
                rules[rule] = rules.get(rule, 0) + 1
            except:
                pass

        if "PID" in line:
            try:
                pids.add(line.split("PID:")[1].split(",")[0].strip())
            except:
                pass

        if "Address" in line:
            try:
                regions.add(line.split("Address:")[1].split(",")[0].strip())
            except:
                pass

    if not rules:
        return "No YARA matches found."

    top_rules = sorted(rules.items(), key=lambda x: x[1], reverse=True)[:25]

    summary = "\n=== YARA MEMORY THREAT SUMMARY ===\n\n"
    summary += f"Total matched rules: {len(rules)}\n"
    summary += f"Total hits: {sum(rules.values())}\n"
    summary += f"Suspicious processes: {', '.join(pids) if pids else 'Unknown'}\n"
    summary += f"Memory regions flagged: {len(regions)}\n\n"

    summary += "Top detected malware signatures:\n"
    summary += "-" * 50 + "\n"

    for rule, count in top_rules:
        summary += f"{rule:40} {count} hits\n"

    summary += "\nRecommendation:\n"
    summary += "- Investigate top PIDs with malfind, dlllist, and handles\n"
    summary += "- Dump memory regions and run static AV/YARA\n"
    summary += "- Correlate with netscan & autoruns\n"

    return summary

