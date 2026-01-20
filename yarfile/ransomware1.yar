rule Ransomware_Engine
{
    strings:
        $a = "encrypt"
        $b = "decrypt"
        $c = "AES"
        $d = "RSA"
        $e = "ChaCha20"
        $f = ".locked"
        $g = ".onion"
    condition:
        3 of them
}

rule ExploitShellcode
{
    strings:
        $a = { 48 31 C0 48 89 C2 48 89 C6 }
        $b = "VirtualAlloc"
        $c = "CreateRemoteThread"
        $d = "WriteProcessMemory"
    condition:
        2 of them
}
