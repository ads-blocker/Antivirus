// Sample YARA rules for EDR — add or replace with your own rule set.
// Rule names and strings are examples; tune for your environment.

rule Suspicious_PE_Resources : malware
{
    meta:
        description = "PE with suspicious resource section pattern"
        author = "EDR"
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

rule High_Entropy_Executable : suspicious
{
    meta:
        description = "Executable with common packer/obfuscation strings"
        author = "EDR"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = ".aspack" ascii
        $d = ".adata" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Script_Dropper_Indicators : malware
{
    meta:
        description = "Script-like or dropper indicators in binary"
        author = "EDR"
    strings:
        $s1 = "powershell" ascii wide
        $s2 = "cmd.exe" ascii wide
        $s3 = "Invoke-" ascii wide
        $s4 = "DownloadString" ascii wide
        $s5 = "FromBase64String" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Suspicious_Import : malware
{
    meta:
        description = "Suspicious API imports often used in malware"
        author = "EDR"
    strings:
        $v = "VirtualAlloc" ascii
        $w = "WriteProcessMemory" ascii
        $x = "CreateRemoteThread" ascii
        $y = "NtUnmapViewOfSection" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
