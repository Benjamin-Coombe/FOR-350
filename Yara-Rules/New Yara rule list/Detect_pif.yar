rule Detect_pif
{
    meta:
        description = "String detect pattern: .pif"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".pif" nocase
    condition:
        $a
}
