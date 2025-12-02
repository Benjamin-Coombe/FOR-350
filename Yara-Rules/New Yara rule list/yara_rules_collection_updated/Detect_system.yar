rule Detect_system
{
    meta:
        description = "String detect pattern: system("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "system(" nocase
    condition:
        $a
}
