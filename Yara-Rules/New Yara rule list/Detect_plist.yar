rule Detect_plist
{
    meta:
        description = "Regex detect pattern: .plist"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.plist/i
    condition:
        $regex
}
