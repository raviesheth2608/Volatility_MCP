from mcp.server.fastmcp import FastMCP
from volatility_tools import run_volatility
import sys
import threading
import uuid

# -------------------------------------------------
# MCP requires STDOUT to be JSON ONLY.
# All logs must go to STDERR.
# -------------------------------------------------

def log(msg):
    print(msg, file=sys.stderr, flush=True)

log("Starting Volatility MCP (Job Engine Mode)")

mcp = FastMCP("Volatility 3 MCP Server – DFIR Job Engine")

# =================================================
# JOB STORAGE
# =================================================

jobs = {}   # job_id -> {status, output}
job_lock = threading.Lock()

# =================================================
# BACKGROUND WORKER
# =================================================

def run_job(job_id, memory_path, plugin, args=None):
    try:
        with job_lock:
            jobs[job_id]["status"] = "running"

        result = run_volatility(memory_path, plugin, args)

        with job_lock:
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["output"] = result

    except Exception as e:
        with job_lock:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["output"] = str(e)

# =================================================
# JOB SUBMISSION
# =================================================

def submit(memory_path, plugin, args=None):
    job_id = str(uuid.uuid4())

    with job_lock:
        jobs[job_id] = {
            "status": "queued",
            "output": None
        }

    t = threading.Thread(
        target=run_job,
        args=(job_id, memory_path, plugin, args),
        daemon=True
    )
    t.start()

    return job_id

# =================================================
# BASIC
# =================================================

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
            return "Invalid job id"
        if job["status"] != "completed":
            return f"Job not finished: {job['status']}"
        return job["output"]

# =================================================
# WINDOWS FORENSICS — JOB MODE
# =================================================

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
def start_malfind(memory_path: str):
    return submit(memory_path, "windows.malfind")

@mcp.tool()
def start_psscan(memory_path: str):
    return submit(memory_path, "windows.psscan")

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

@mcp.tool()
def start_yarascan(memory_path: str, yara_rule_path: str):
    return submit(
        memory_path,
        "windows.yarascan",
        ["--yara-file", yara_rule_path]
    )

# =================================================
# ENTRY
# =================================================

if __name__ == "__main__":
    log("Volatility MCP running in job mode")
    mcp.run()
