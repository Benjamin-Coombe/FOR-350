rule Detect_require_fs_writeFileSync
{
    meta:
        description = "String detect pattern: require('fs').writeFileSync("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('fs').writeFileSync(" nocase
    condition:
        $a
}
