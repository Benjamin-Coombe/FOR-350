rule Detect_require_child_process_execFile
{
    meta:
        description = "String detect pattern: require('child_process').execFile("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('child_process').execFile(" nocase
    condition:
        $a
}
