rule Detect_cmd_c
{
    meta:
        description = "String detect pattern: cmd /c"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "cmd /c" nocase
    condition:
        $a
}
