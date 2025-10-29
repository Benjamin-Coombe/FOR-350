rule Detect_htm_or_html
{
    meta:
        description = "Regex detect pattern: .htm or .html"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.htm\ or\ \.html/i
    condition:
        $regex
}
