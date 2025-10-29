rule Detect_passthru
{
    meta:
        description = "String detect pattern: passthru("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "passthru(" nocase
    condition:
        $a
}
