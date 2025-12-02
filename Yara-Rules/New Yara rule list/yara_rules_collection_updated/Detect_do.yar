rule Detect_do
{
    meta:
        description = "String detect pattern: do("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "do(" nocase
    condition:
        $a
}
