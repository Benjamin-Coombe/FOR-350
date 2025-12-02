rule Detect_exec
{
    meta:
        description = "String detect pattern: exec("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "exec(" nocase
    condition:
        $a
}
