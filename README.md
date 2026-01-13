# Volatility_MCP
A timeout-proof Volatility 3 MCP server for Claude Desktop with a background job engine, enabling long-running memory forensics, malware detection, YARA scanning, and DFIR workflows without hitting Claude’s 4-minute tool limit.

# Volatility MCP – Claude Desktop DFIR Server

A **timeout-proof Volatility 3 MCP server** for Claude Desktop using a **background job engine**.

This allows Claude to run:
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

```bash
git clone https://github.com/YOURNAME/volatility-mcp
cd volatility-mcp
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

