rule Detect_base64_decode
{
    meta:
        description = "String detect pattern: base64_decode("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "base64_decode(" nocase
    condition:
        $a
}
