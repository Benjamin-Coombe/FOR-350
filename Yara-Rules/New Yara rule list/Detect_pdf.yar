rule Detect_pdf
{
    meta:
        description = "String detect pattern: .pdf"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".pdf" nocase
    condition:
        $a
}
