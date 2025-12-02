rule Detect_eval
{
    meta:
        description = "String detect pattern: eval("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "eval(" nocase
    condition:
        $a
}
