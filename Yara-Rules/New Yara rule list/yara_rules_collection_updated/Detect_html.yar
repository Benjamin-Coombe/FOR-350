rule Detect_html
{
    meta:
        description = "String detect pattern: .html"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".html" nocase
    condition:
        $a
}
