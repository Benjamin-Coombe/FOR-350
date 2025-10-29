rule Detect_escapeshellcmd
{
    meta:
        description = "String detect pattern: escapeshellcmd("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "escapeshellcmd(" nocase
    condition:
        $a
}
