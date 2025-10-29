rule Detect_Execute
{
    meta:
        description = "String detect pattern: Execute("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Execute(" nocase
    condition:
        $a
}
