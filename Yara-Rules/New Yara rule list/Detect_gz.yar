rule Detect_gz
{
    meta:
        description = "Regex detect pattern: .gz"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.gz/i
    condition:
        $regex
}
