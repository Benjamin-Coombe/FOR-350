rule Detect_fopen
{
    meta:
        description = "String detect pattern: fopen("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "fopen(" nocase
    condition:
        $a
}
