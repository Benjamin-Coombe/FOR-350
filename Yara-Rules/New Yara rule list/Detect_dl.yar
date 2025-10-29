rule Detect_dl
{
    meta:
        description = "String detect pattern: dl("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "dl(" nocase
    condition:
        $a
}
