rule Detect_Eval
{
    meta:
        description = "String detect pattern: Eval("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Eval(" nocase
    condition:
        $a
}
