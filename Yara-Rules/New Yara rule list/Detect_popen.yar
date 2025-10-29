rule Detect_popen
{
    meta:
        description = "String detect pattern: popen("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "popen(" nocase
    condition:
        $a
}
