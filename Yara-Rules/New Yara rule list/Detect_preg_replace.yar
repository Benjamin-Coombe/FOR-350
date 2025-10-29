rule Detect_preg_replace
{
    meta:
        description = "String detect pattern: preg_replace("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "preg_replace(" nocase
    condition:
        $a
}
