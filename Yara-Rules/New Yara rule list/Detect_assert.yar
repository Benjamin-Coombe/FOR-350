rule Detect_assert
{
    meta:
        description = "String detect pattern: assert("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "assert(" nocase
    condition:
        $a
}
