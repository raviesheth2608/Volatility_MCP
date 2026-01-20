/*
================================================================
 ULTIMATE DFIR YARA PACK
 For Volatility 3 + Claude MCP
 Covers:
  - APTs
  - Ransomware
  - RATs
  - Loaders
  - Exploits
  - Memory Injection
  - Fileless Malware
  - Credential Theft
  - C2 Beacons
================================================================
*/

import "pe"

/* =========================
   APT THREAT ACTORS
   ========================= */

rule APT29_CozyBear {
    meta:
        threat = "APT29"
        type = "Nation State"
    strings:
        $a = "invoke-mimikatz"
        $b = "posh_c2"
        $c = "Microsoft.Exchange.WebServices"
    condition:
        2 of them
}

rule Lazarus_Group {
    meta:
        threat = "Lazarus"
        type = "North Korea"
    strings:
        $a = "FASTCash"
        $b = "Destover"
        $c = "SWIFT"
    condition:
        1 of them
}

rule APT41 {
    meta:
        threat = "APT41"
    strings:
        $a = "Cobalt Strike"
        $b = "China Chopper"
        $c = "PlugX"
    condition:
        1 of them
}

/* =========================
   RANSOMWARE FAMILIES
   ========================= */

rule LockBit {
    strings:
        $a = "lockbit"
        $b = ".lockbit"
        $c = "locker.exe"
    condition:
        1 of them
}

rule Conti {
    strings:
        $a = "conti"
        $b = "Ryuk"
        $c = "TrickBot"
    condition:
        1 of them
}

rule BlackCat_ALPHV {
    strings:
        $a = "ALPHV"
        $b = "BlackCat"
        $c = ".onion"
    condition:
        1 of them
}

rule Ransomware_Encryption {
    strings:
        $a = "AES"
        $b = "RSA"
        $c = "ChaCha20"
        $d = "encrypt"
        $e = "decrypt"
        $f = ".locked"
    condition:
        3 of them
}

/* =========================
   REMOTE ACCESS TROJANS
   ========================= */

rule RAT_Remcos {
    strings:
        $a = "Remcos"
        $b = "remcos.exe"
        $c = "Command Manager"
    condition:
        1 of them
}

rule RAT_DarkComet {
    strings:
        $a = "DarkComet"
        $b = "DC RAT"
        $c = "funny.exe"
    condition:
        1 of them
}

rule RAT_NjRAT {
    strings:
        $a = "njRAT"
        $b = "Bladabindi"
        $c = "SocketMessage"
    condition:
        1 of them
}

/* =========================
   LOADERS & DROPPERS
   ========================= */

rule Loader_Emotet {
    strings:
        $a = "emotet"
        $b = "Geodo"
        $c = "Outlook.Application"
    condition:
        1 of them
}

rule Loader_QakBot {
    strings:
        $a = "QakBot"
        $b = "Qbot"
        $c = "wermgr.exe"
    condition:
        1 of them
}

/* =========================
   CREDENTIAL THEFT
   ========================= */

rule Mimikatz {
    strings:
        $a = "mimikatz"
        $b = "sekurlsa"
        $c = "logonpasswords"
    condition:
        1 of them
}

rule LSASS_Dump {
    strings:
        $a = "lsass.exe"
        $b = "MiniDumpWriteDump"
    condition:
        all of them
}

/* =========================
   FILELESS ATTACKS
   ========================= */

rule PowerShell_Fileless {
    strings:
        $a = "powershell -enc"
        $b = "IEX("
        $c = "FromBase64String"
        $d = "DownloadString"
    condition:
        2 of them
}

/* =========================
   MEMORY INJECTION
   ========================= */

rule ProcessInjection {
    strings:
        $a = "VirtualAlloc"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtMapViewOfSection"
    condition:
        2 of them
}

rule ReflectiveDLL {
    strings:
        $a = "ReflectiveLoader"
        $b = "LoadLibraryA"
    condition:
        1 of them
}

/* =========================
   SHELLCODE
   ========================= */

rule Shellcode {
    strings:
        $a = { 90 90 90 90 }
        $b = { FC 48 83 E4 F0 }
    condition:
        any of them
}

/* =========================
   COMMAND & CONTROL
   ========================= */

rule C2_Beacon {
    strings:
        $a = "/gate.php"
        $b = "/panel/login"
        $c = "POST /api"
        $d = ".onion"
    condition:
        1 of them
}

/* =========================
   KEYLOGGERS
   ========================= */

rule Keylogger {
    strings:
        $a = "GetAsyncKeyState"
        $b = "SetWindowsHookEx"
        $c = "keylog"
    condition:
        1 of them
}
