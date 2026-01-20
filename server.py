from mcp.server.fastmcp import FastMCP
from volatility_tools import run_volatility, summarize_yara_results
import sys
import threading
import uuid
import os

# =========================================================
# MCP RULE: STDOUT must be JSON, all logs go to STDERR
# =========================================================

def log(msg):
    print(msg, file=sys.stderr, flush=True)

log("Starting Volatility MCP – Enterprise Job Engine - Dr Ravi Sheth")

mcp = FastMCP("Volatility 3 MCP – DFIR Job Engine ")

# =========================================================
# CONFIG
# =========================================================

MAX_CLAUDE_OUTPUT = 100_000   # Safe size for Claude (~100 KB)
RESULT_DIR = r"C:\volatility-mcp\results"

os.makedirs(RESULT_DIR, exist_ok=True)
log(f"Results directory resolved to: {RESULT_DIR}")
test_file = os.path.join(RESULT_DIR, "write_test.txt")
try:
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    log("Result directory is writable")
except Exception as e:
    log(f"[CRITICAL] Result directory NOT writable: {e}")

import os
from datetime import datetime

# In your MCP server code, add file writing functionality
def save_results_to_file(plugin_name, results, output_dir="C:\\volatility-mcp\\results"):
    """Save Volatility results to file"""
    
    # Create results directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{plugin_name}_{timestamp}.txt"
    filepath = os.path.join(output_dir, filename)
    
    # Write results to file
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(results)
        return filepath
    except Exception as e:
        print(f"Error saving results: {e}")
        return None


# =========================================================
# JOB STORAGE
# =========================================================

jobs = {}   # job_id → {status, output, plugin, is_yara, file}
job_lock = threading.Lock()

# =========================================================
# OUTPUT MANAGEMENT
# =========================================================


def safe_store(job_id, output):
    """
    Store full output on disk if too large for Claude
    """
    try:
        if len(output) <= MAX_CLAUDE_OUTPUT:
            return output, None

        filename = os.path.join(RESULT_DIR, f"{job_id}.txt")

        with open(filename, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)

        msg = (
            "⚠️ Output too large for Claude.\n\n"
            f"Full results saved to:\n{filename}\n\n"
            "Use job_file to retrieve path."
        )

        return msg, filename

    except Exception as e:
        log(f"[FILE WRITE ERROR] {e}")
        return "Output too large, but file write failed.", None

# =========================================================
# BACKGROUND WORKER
# =========================================================

def run_job(job_id, memory_path, plugin, args=None):
    try:
        with job_lock:
            jobs[job_id]["status"] = "running"

        result = run_volatility(memory_path, plugin, args)

        # ALWAYS write full output to disk
        filename = os.path.join(RESULT_DIR, f"{job_id}_{plugin}.txt")
        with open(filename, "w", encoding="utf-8", errors="replace") as f:
            f.write(result)

        # Handle Claude-safe output
        safe_output, _ = safe_store(job_id, result)

        with job_lock:
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["output"] = safe_output
            jobs[job_id]["file"] = filename

        log(f"[SAVED] {filename}")

    except Exception as e:
        log(f"[JOB ERROR] {e}")
        with job_lock:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["output"] = str(e)


# =========================================================
# JOB SUBMISSION
# =========================================================

def submit(memory_path, plugin, args=None, is_yara=False):
    job_id = str(uuid.uuid4())

    with job_lock:
        jobs[job_id] = {
            "status": "queued",
            "output": None,
            "plugin": plugin,
            "is_yara": is_yara,
            "file": None
        }

    t = threading.Thread(
        target=run_job,
        args=(job_id, memory_path, plugin, args),
        daemon=True
    )
    t.start()

    return job_id

# =========================================================
# BASIC MCP TOOLS
# =========================================================

@mcp.tool()
def ping():
    return "pong"

@mcp.tool()
def job_status(job_id: str):
    with job_lock:
        return jobs.get(job_id, {"status": "unknown"})

@mcp.tool()
def job_result(job_id: str):
    with job_lock:
        job = jobs.get(job_id)

    if not job:
        return "Invalid job ID"

    if job["status"] != "completed":
        return f"Job not finished: {job['status']}"

    # If YARA → summarize
    if job.get("is_yara"):
        return summarize_yara_results(job["output"])

    return job["output"]

@mcp.tool()
def job_file(job_id: str):
    with job_lock:
        job = jobs.get(job_id)

    if not job or not job.get("file"):
        return "No file for this job"

    return job["file"]

# =========================================================
# WINDOWS FORENSICS
# =========================================================

@mcp.tool()
def start_windows_info(memory_path: str):
    return submit(memory_path, "windows.info")

@mcp.tool()
def start_pslist(memory_path: str):
    return submit(memory_path, "windows.pslist")

@mcp.tool()
def start_pstree(memory_path: str):
    return submit(memory_path, "windows.pstree")

@mcp.tool()
def start_cmdline(memory_path: str):
    return submit(memory_path, "windows.cmdline")

@mcp.tool()
def start_psscan(memory_path: str):
    return submit(memory_path, "windows.psscan")

@mcp.tool()
def start_malfind(memory_path: str):
    return submit(memory_path, "windows.malfind")

@mcp.tool()
def start_threads(memory_path: str):
    return submit(memory_path, "windows.threads")

@mcp.tool()
def start_dlllist(memory_path: str, pid: int):
    return submit(memory_path, "windows.dlllist", ["--pid", str(pid)])

@mcp.tool()
def start_ldrmodules(memory_path: str):
    return submit(memory_path, "windows.ldrmodules")

@mcp.tool()
def start_netscan(memory_path: str):
    return submit(memory_path, "windows.netscan")

@mcp.tool()
def start_autoruns(memory_path: str):
    return submit(memory_path, "windows.autoruns")

@mcp.tool()
def start_ssdt(memory_path: str):
    return submit(memory_path, "windows.ssdt")

@mcp.tool()
def start_callbacks(memory_path: str):
    return submit(memory_path, "windows.callbacks")

# =========================================================
# YARA (SAFE MODE)
# =========================================================

@mcp.tool()
def start_yarascan(memory_path: str, yara_rule_path: str):
    return submit(
        memory_path,
        "yarascan.YaraScan",
        ["--yara-file", yara_rule_path],
        is_yara=True
    )

# =========================================================
# ENTRY
# =========================================================

if __name__ == "__main__":
    log("Volatility MCP ready (Job Engine Mode)")
    mcp.run()
