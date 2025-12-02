rule Detect_include
{
    meta:
        description = "String detect pattern: include("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "include(" nocase
    condition:
        $a
}
