rule Detect_xls
{
    meta:
        description = "Regex detect pattern: .xls"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.xls/i
    condition:
        $regex
}
