rule Detect_require_fs_readFileSync
{
    meta:
        description = "String detect pattern: require('fs').readFileSync("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('fs').readFileSync(" nocase
    condition:
        $a
}
