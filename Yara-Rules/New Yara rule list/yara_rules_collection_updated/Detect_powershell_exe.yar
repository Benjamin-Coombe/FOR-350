rule Detect_powershell_exe
{
    meta:
        description = "String detect pattern: “powershell.exe “"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "“powershell.exe “" nocase
    condition:
        $a
}
