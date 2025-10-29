rule Detect_gzinflate
{
    meta:
        description = "String detect pattern: gzinflate("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "gzinflate(" nocase
    condition:
        $a
}
