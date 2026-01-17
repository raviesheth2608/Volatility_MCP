rule Rootkit_Hooking
{
    meta:
        description = "Kernel API hooking"
        severity = "critical"

    strings:
        $a = "KeServiceDescriptorTable"
        $b = "SSDT"
        $c = "NtQuerySystemInformation"
        $d = "ZwQuerySystemInformation"

    condition:
        2 of them
}

rule DKOM
{
    meta:
        description = "Direct Kernel Object Manipulation"

    strings:
        $a = "EPROCESS"
        $b = "ActiveProcessLinks"
        $c = "HiddenProcess"

    condition:
        2 of them
}
