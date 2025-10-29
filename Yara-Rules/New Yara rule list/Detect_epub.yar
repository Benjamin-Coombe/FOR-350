rule Detect_epub
{
    meta:
        description = "Regex detect pattern: .epub"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.epub/i
    condition:
        $regex
}
