rule Detect_vhd
{
    meta:
        description = "Regex detect pattern: .vhd"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.vhd/i
    condition:
        $regex
}
