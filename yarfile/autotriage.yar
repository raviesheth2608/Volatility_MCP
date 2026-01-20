rule Suspicious_Memory_Behavior
{
    meta:
        author = "Volatility MCP"
        severity = "high"
        description = "Generic malware behaviors in memory"

    strings:
        $a = "powershell -enc" ascii
        $b = "cmd.exe /c" ascii
        $c = "rundll32" ascii
        $d = "wscript.shell" ascii
        $e = "schtasks /create" ascii
        $f = "reg add" ascii
        $g = "mimikatz" ascii
        $h = "lsass.exe" ascii
        $i = "ReflectiveLoader" ascii
        $j = "VirtualAlloc" ascii
        $k = "WriteProcessMemory" ascii

    condition:
        3 of them
}

rule Ransomware_Memory
{
    strings:
        $a = "AES" wide
        $b = "RSA" wide
        $c = "ChaCha20"
        $d = "encrypt" wide
        $e = ".locked" wide
        $f = ".encrypted" wide
        $g = ".lockbit" wide

    condition:
        3 of them
}

rule CobaltStrike_Memory
{
    strings:
        $a = "beacon.dll"
        $b = "ArtifactKit"
        $c = "Malleable"
        $d = "postex"
        $e = "\\\\.\\pipe\\msagent_"

    condition:
        2 of them
}

rule Kernel_Rootkit
{
    strings:
        $a = "SSDT"
        $b = "KeServiceDescriptorTable"
        $c = "ZwQuerySystemInformation"
        $d = "EPROCESS"
        $e = "ActiveProcessLinks"

    condition:
        2 of them
}
