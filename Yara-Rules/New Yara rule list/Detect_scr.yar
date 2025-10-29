rule Detect_scr
{
    meta:
        description = "Regex detect pattern: .scr"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.scr/i
    condition:
        $regex
}
