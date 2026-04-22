rule PowerShell_Encoded_Command : suspicious {
    strings:
        $a = "powershell -enc" nocase
        $b = "frombase64string" nocase
        $c = "invoke-expression" nocase
    condition:
        2 of them
}

rule PowerShell_Download_Exec : high {
    strings:
        $a = "downloadstring(" nocase
        $b = "invoke-expression" nocase
        $c = "powershell" nocase
    condition:
        all of them
}
