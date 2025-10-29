rule Detect_require_child_process_execFileSync
{
    meta:
        description = "String detect pattern: require('child_process').execFileSync("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('child_process').execFileSync(" nocase
    condition:
        $a
}
