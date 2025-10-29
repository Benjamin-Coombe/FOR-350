rule Detect_rtf
{
    meta:
        description = "String detect pattern: .rtf"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".rtf" nocase
    condition:
        $a
}
