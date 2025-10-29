rule Detect_require_fs_readFile
{
    meta:
        description = "String detect pattern: require('fs').readFile("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('fs').readFile(" nocase
    condition:
        $a
}
