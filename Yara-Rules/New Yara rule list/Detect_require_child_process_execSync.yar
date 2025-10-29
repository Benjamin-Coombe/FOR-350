rule Detect_require_child_process_execSync
{
    meta:
        description = "String detect pattern: require('child_process').execSync("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('child_process').execSync(" nocase
    condition:
        $a
}
