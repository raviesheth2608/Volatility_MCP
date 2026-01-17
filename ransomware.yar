rule Ransomware_Core
{
    meta:
        description = "Generic ransomware memory patterns"
        severity = "critical"

    strings:
        $a = "AES" wide
        $b = "RSA" wide
        $c = "ChaCha20" ascii
        $d = "encrypt" wide
        $e = "decrypt" wide
        $f = "crypt" wide

    condition:
        3 of them
}

rule Ransomware_Extensions
{
    strings:
        $a = ".locked" wide
        $b = ".encrypted" wide
        $c = ".crypt" wide
        $d = ".wannacry" wide
        $e = ".lockbit" wide

    condition:
        any of them
}
