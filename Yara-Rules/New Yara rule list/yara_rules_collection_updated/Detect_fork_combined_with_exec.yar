rule Detect_fork_combined_with_exec
{
    meta:
        description = "String detect pattern: fork( combined with exec("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "fork( combined with exec(" nocase
    condition:
        $a
}
