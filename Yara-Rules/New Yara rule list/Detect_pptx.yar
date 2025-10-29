rule Detect_pptx
{
    meta:
        description = "String detect pattern: .pptx"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".pptx" nocase
    condition:
        $a
}
