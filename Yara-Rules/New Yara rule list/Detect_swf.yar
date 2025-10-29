rule Detect_swf
{
    meta:
        description = "Regex detect pattern: .swf"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.swf/i
    condition:
        $regex
}
