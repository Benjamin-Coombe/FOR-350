rule Detect_require_once
{
    meta:
        description = "String detect pattern: require_once("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require_once(" nocase
    condition:
        $a
}
