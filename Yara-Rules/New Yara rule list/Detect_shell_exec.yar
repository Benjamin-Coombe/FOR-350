rule Detect_shell_exec
{
    meta:
        description = "String detect pattern: shell_exec("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "shell_exec(" nocase
    condition:
        $a
}
