rule Detect_pageContext_include
{
    meta:
        description = "String detect pattern: pageContext.include("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "pageContext.include(" nocase
    condition:
        $a
}
