rule Detect_require_fs_writeFile
{
    meta:
        description = "String detect pattern: require('fs').writeFile("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('fs').writeFile(" nocase
    condition:
        $a
}
