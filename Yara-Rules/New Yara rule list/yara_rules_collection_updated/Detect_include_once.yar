rule Detect_include_once
{
    meta:
        description = "String detect pattern: include_once("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "include_once(" nocase
    condition:
        $a
}
