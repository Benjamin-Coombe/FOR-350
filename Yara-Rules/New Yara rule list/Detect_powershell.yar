rule Detect_powershell
{
    meta:
        description = "String detect pattern: “powershell ”"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "“powershell ”" nocase
    condition:
        $a
}
