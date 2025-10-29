rule Detect_ppt
{
    meta:
        description = "Regex detect pattern: .ppt"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.ppt/i
    condition:
        $regex
}
