rule Detect_fwrite
{
    meta:
        description = "String detect pattern: fwrite("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "fwrite(" nocase
    condition:
        $a
}
