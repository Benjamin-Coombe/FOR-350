rule Detect_ASP_VBScript
{
    meta:
        description = "String detect pattern: ASP (VBScript)"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "ASP (VBScript)" nocase
    condition:
        $a
}
