rule Detect_cur
{
    meta:
        description = "Regex detect pattern: .cur"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.cur/i
    condition:
        $regex
}
