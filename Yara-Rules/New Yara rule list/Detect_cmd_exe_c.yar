rule Detect_cmd_exe_c
{
    meta:
        description = "String detect pattern: cmd.exe /c"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "cmd.exe /c" nocase
    condition:
        $a
}
