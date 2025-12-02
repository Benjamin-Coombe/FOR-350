rule Detect_urldecode
{
    meta:
        description = "String detect pattern: urldecode("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "urldecode(" nocase
    condition:
        $a
}
