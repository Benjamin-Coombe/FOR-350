rule Detect_htm
{
    meta:
        description = "String detect pattern: .htm"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".htm" nocase
    condition:
        $a
}
