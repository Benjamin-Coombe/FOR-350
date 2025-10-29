rule Detect_use
{
    meta:
        description = "String detect pattern: use("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "use(" nocase
    condition:
        $a
}
