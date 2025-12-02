rule Detect_require
{
    meta:
        description = "String detect pattern: require("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require(" nocase
    condition:
        $a
}
