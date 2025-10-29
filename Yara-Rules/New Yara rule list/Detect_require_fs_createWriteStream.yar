rule Detect_require_fs_createWriteStream
{
    meta:
        description = "String detect pattern: require('fs').createWriteStream("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('fs').createWriteStream(" nocase
    condition:
        $a
}
