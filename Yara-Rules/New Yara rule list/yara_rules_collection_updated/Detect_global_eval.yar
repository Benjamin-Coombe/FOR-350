rule Detect_global_eval
{
    meta:
        description = "String detect pattern: global.eval("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "global.eval(" nocase
    condition:
        $a
}
