rule Detect_xlsx
{
    meta:
        description = "String detect pattern: .xlsx"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".xlsx" nocase
    condition:
        $a
}
