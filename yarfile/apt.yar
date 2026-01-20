rule APT_Backdoor
{
    meta:
        description = "Nation-state backdoor indicators"
        severity = "critical"

    strings:
        $a = "cmd.exe /c" ascii
        $b = "powershell -enc" ascii
        $c = "wscript.shell" ascii
        $d = "schtasks /create" ascii
        $e = "reg add" ascii

    condition:
        2 of them
}

rule APT_C2
{
    strings:
        $a = "POST /gate.php" ascii
        $b = "User-Agent: Mozilla" ascii
        $c = "Authorization: Bearer" ascii
        $d = "api.php?id=" ascii

    condition:
        2 of them
}
