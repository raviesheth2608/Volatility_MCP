# Claude + MCP + Volatility 3 = AI-powered Windows Memory Forensics
A timeout-proof Volatility 3 MCP server for Claude Desktop with a background job engine, enabling long-running memory forensics, malware detection, YARA scanning, and DFIR workflows without hitting Claude’s 4-minute tool limit.

# Volatility MCP – Claude Desktop DFIR Server

A **timeout-proof Volatility 3 MCP server** for Claude Desktop using a **background job engine**.

This allows Claude to run:
- pslist, psscan , pstree, netscan 
- Malfind
- YARA
- Netscan
- Autoruns
- Rootkit detection
- Full memory forensics

without hitting Claude Desktop’s 4-minute tool execution limit.

---

## 🚀 Features

- Runs **30–60 minute Volatility scans** without timeout
- Background job engine (submit → poll → fetch)
- Works on Windows
- Compatible with Claude Desktop MCP
- Supports all major Volatility 3 plugins

---

## 🛠 Installation

1️⃣ Install Python
Download Python from
👉 https://www.python.org/downloads/windows/
During installation:
✅ Check “Add Python to PATH”
✅ Check “Install pip”
Verify in CMD
python --version
pip --version

2️⃣ Install Git
Download from
👉 https://git-scm.com/downloads
Verify in CMD:
git --version

3️⃣ Clone the Repository
in CMD
cd C:\
git clone https://github.com/YOURNAME/volatility-mcp.git
cd volatility-mcp

4️⃣ Create Python Virtual Environment
in CMD
python -m venv venv
venv\Scripts\activate
You should see:
(venv)

5️⃣ Install Dependencies
in CMD
pip install --upgrade pip
pip install volatility3 mcp fastmcp yara-python

6️⃣ Add Your Memory Dump at specific location

7️⃣ Configure Claude Desktop MCP

{
  "mcpServers": {
    "volatility": {
      "command": "C:\\volatility-mcp\\venv\\Scripts\\python.exe",
      "args": [
        "-u",
        "C:\\volatility-mcp\\server.py"
      ]
    }
  }
}

windows
down load Volatility_MCP folder save it at C:
open cmd and set the location C:\Volatility_MCP
C:\Volatility_MCP python -m venv venv
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install .

