rule Common_Process_Injection_Pattern : suspicious {
    strings:
        $a = "VirtualAllocEx" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "CreateRemoteThread" ascii wide
    condition:
        2 of them
}

rule LOLBin_Mshta_Rundll32 : suspicious {
    strings:
        $a = "mshta" nocase
        $b = "rundll32" nocase
    condition:
        all of them
}
