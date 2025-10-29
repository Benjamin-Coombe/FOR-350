rule Detect_lnk
{
    meta:
        description = "String detect pattern: .lnk"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".lnk" nocase
    condition:
        $a
}
