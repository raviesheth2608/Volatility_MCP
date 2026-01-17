rule APT29_CozyBear
{
    meta:
        actor = "APT29 / Cozy Bear"
        country = "Russia"
    strings:
        $a = "posh_c2"
        $b = "invoke-mimikatz"
        $c = "Outlook.dll"
        $d = "Microsoft.Exchange.WebServices"
    condition:
        2 of them
}

rule Lazarus_Group
{
    meta:
        actor = "Lazarus"
        country = "North Korea"
    strings:
        $a = "FASTCash"
        $b = "Destover"
        $c = "Bankshot"
        $d = "SWIFT"
    condition:
        1 of them
}

rule FIN7
{
    meta:
        actor = "FIN7"
    strings:
        $a = "Carbanak"
        $b = "GrimPlant"
        $c = "PowerPlant"
    condition:
        1 of them
}

rule LockBit
{
    meta:
        actor = "LockBit Ransomware"
    strings:
        $a = "lockbit"
        $b = "BlackMatter"
        $c = "locker.exe"
        $d = ".lockbit"
    condition:
        1 of them
}
