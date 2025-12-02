rule Detect_create_function
{
    meta:
        description = "String detect pattern: create_function("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "create_function(" nocase
    condition:
        $a
}
