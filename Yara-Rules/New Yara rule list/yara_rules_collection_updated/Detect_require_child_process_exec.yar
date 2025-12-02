rule Detect_require_child_process_exec
{
    meta:
        description = "String detect pattern: require('child_process').exec("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('child_process').exec(" nocase
    condition:
        $a
}
