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

- 1️⃣ Install Python
Download Python from
👉 https://www.python.org/downloads/windows/
During installation:
✅ Check “Add Python to PATH”
✅ Check “Install pip”
Verify in CMD
python --version
pip --version

- 2️⃣ Install Git
Download from
👉 https://git-scm.com/downloads
-Verify in CMD: git --version

- 3️⃣ Clone the Repository
- in CMD
- cd C:\
- git clone https://github.com/YOURNAME/volatility-mcp.git
- cd volatility-mcp

- 4️⃣ Create Python Virtual Environment
- in CMD (C:\Volatility_MCP)
- python -m venv venv
- venv\Scripts\activate
-You should see:(venv)

- 5️⃣ Install Dependencies
- insind <vnev>
- pip install --upgrade pip
- pip install mcp volatility3 yara-python
- pip list
You must see:
-volatility3
-mcp
-veryify with this command (C:\volatility-mcp\venv\Scripts\vol.exe -h)

- 6️⃣ Add Your Memory Dump at specific location

- 7️⃣ Configure Claude Desktop MCP (download from: https://claude.com/download)
- location of .json file
- in my case it is : C:\Users\nameofuser\AppData\Roaming\Claude\claude_desktop_config.json
- update the json file with follwing code
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
Save → Restart Claude Desktop.
close it and restart your PC/Laptop 

- 8️⃣ Open CMD
First start the server.py file
C:\Volatility_MCP\python server.py

- 9️⃣ Open claude desktop application and wait for few seconds 
opne file-> Settings-> developer (If everything is ok -> You can see volatility server is running)

- 🔟 open chat and start process for memory annlysis: best prompt : 

- Run windows.info and windows.pslist on the memory dump located at C:\Volatility_MCP\memdump.mem
- Run windows.pstree, windows.cmdline, and windows.psscan on C:\Volatility_MCP\memdump.mem
- Run windows.malfind on C:\Volatility_MCP\memdump.mem
- Run windows.dlllist on C:\Volatility_MCP\memdump.mem




