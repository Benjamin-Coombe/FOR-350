rule Detect_copy
{
    meta:
        description = "String detect pattern: copy("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "copy(" nocase
    condition:
        $a
}
