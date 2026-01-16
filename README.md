# 🧠 Claude + MCP + Volatility 3  
### AI-Powered Windows Memory Forensics

A **timeout-proof Volatility 3 MCP server** for **Claude Desktop** that enables **long-running memory forensics, malware hunting, YARA scanning, and DFIR workflows** without hitting Claude’s 4-minute tool execution limit.

---

# 🔥 Volatility MCP – Claude Desktop DFIR Server

This project connects **Claude Desktop** to **Volatility 3** using the **Model Context Protocol (MCP)** so Claude can directly analyze Windows memory dumps.

It allows Claude to run:

- pslist, psscan, pstree, cmdline  
- malfind  
- netscan  
- autoruns  
- dlllist, ldrmodules  
- rootkit detection  
- YARA scanning  
- full DFIR memory workflows  

…without timing out.

---

# 🚀 Features

- Runs **30–60 minute Volatility scans** without Claude timing out  
- Works on **Windows**  
- Integrates directly with **Claude Desktop MCP**  
- Supports **all major Volatility 3 plugins**  
- Malware detection, network forensics, persistence, rootkits, YARA  

---

# 🛠 System Requirements

| Component | Required |
|--------|----------|
| Windows | Windows 10 / 11 |
| Python | 3.10+ |
| Claude Desktop | Latest |
| Git | Installed |
| Memory Dump | `.mem`, `.raw`, `.dmp` |

---

# 📦 Installation (Windows)

## 1️⃣ Install Python

Download  
https://www.python.org/downloads/windows/

During install:
- ✔ Add Python to PATH  
- ✔ Install pip  

Verify:
```cmd
python --version
pip --version
```

---

## 2️⃣ Install Git

Download  
https://git-scm.com/downloads

Verify:
```cmd
git --version
```

---

## 3️⃣ Clone Repository

```cmd
cd C:\
git clone https://github.com/raviesheth2608/Volatility_MCP.git
cd volatility-mcp
```

---

## 4️⃣ Create Virtual Environment

```cmd
python -m venv venv
venv\Scripts\activate
```

You should see:
```
(venv)
```

---

## 5️⃣ Install Dependencies

```cmd
pip install --upgrade pip
pip install -r requirements.txt
```

Verify:
```cmd
pip list
```

You should see:
- volatility3  
- mcp  
- fastmcp  
- yara-python  

Test Volatility:
```cmd
C:\volatility-mcp\venv\Scripts\vol.exe -h
```

---

## 6️⃣ Add Memory Dump

Place your memory image here:
```
C:\volatility-mcp\memdump.mem
```

---

# 🧩 Claude Desktop MCP Configuration

Install Claude Desktop  
https://claude.com/download  

Open:
```
C:\Users\YOURNAME\AppData\Roaming\Claude\claude_desktop_config.json
```

Add:

```json
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
```

Save → Close Claude → Restart Windows

---

# ▶ Start MCP Server

```cmd
cd C:\volatility-mcp
venv\Scripts\activate
python server.py
```

You should see:
```
Volatility MCP Server running
```

---

# 🔌 Open Claude and Verify

Claude Desktop →  
Settings → Developer  

You should see:
```
volatility   ✔ Connected
```

---

# 🧠 Claude Prompts

System info:
```
Run windows.info and windows.pslist on C:\volatility-mcp\memdump.mem
```

Process tree:
```
Run windows.pstree, windows.cmdline, and windows.psscan on C:\volatility-mcp\memdump.mem
```

Malware:
```
Run windows.malfind on C:\volatility-mcp\memdump.mem
```

DLLs:
```
Run windows.dlllist on C:\volatility-mcp\memdump.mem
```

Network:
```
Run windows.netscan on C:\volatility-mcp\memdump.mem
```

Persistence:
```
Run windows.autoruns on C:\volatility-mcp\memdump.mem
```

YARA:
```
Run windows.yarascan with my YARA rule on C:\volatility-mcp\memdump.mem
```

---

# 🧪 Manual Volatility Test

```cmd
C:\volatility-mcp\venv\Scripts\vol.exe -f C:\volatility-mcp\memdump.mem windows.info
```

If this works → MCP will work.

---

# 📦 requirements.txt

```
mcp
fastmcp
volatility3
yara-python
pefile
capstone
psutil
requests
rich
```

---

# 🛡 What You Built

You now have an **AI-powered memory forensics engine** where Claude acts like a:

- Malware analyst  
- DFIR investigator  
- Threat hunter  
- SOC analyst  

inside your own Windows lab.

Welcome to **AI-driven digital forensics** 🧠🔥
