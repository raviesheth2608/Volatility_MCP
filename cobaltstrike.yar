rule CobaltStrike_Beacon
{
    meta:
        author = "Volatility MCP"
        description = "Cobalt Strike beacon in memory"
        severity = "critical"

    strings:
        $a = "beacon.dll" ascii
        $b = "ArtifactKit" ascii
        $c = "Malleable" ascii
        $d = "ReflectiveLoader" ascii
        $e = "cobaltstrike" ascii

    condition:
        2 of them
}

rule CobaltStrike_Pipe
{
    meta:
        description = "Named pipes used by Cobalt Strike"

    strings:
        $a = "\\\\.\\pipe\\msagent_" ascii
        $b = "\\\\.\\pipe\\postex_" ascii
        $c = "\\\\.\\pipe\\mojo" ascii

    condition:
        any of them
}
