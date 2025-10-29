rule Detect_docx
{
    meta:
        description = "String detect pattern: .docx"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".docx" nocase
    condition:
        $a
}
