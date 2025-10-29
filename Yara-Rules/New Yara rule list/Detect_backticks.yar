rule Detect_backticks
{
    meta:
        description = "String detect pattern: backticks"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "backticks" nocase
    condition:
        $a
}
