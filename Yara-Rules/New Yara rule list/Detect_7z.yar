rule Detect_7z
{
    meta:
        description = "String detect pattern: .7z"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".7z" nocase
    condition:
        $a
}
