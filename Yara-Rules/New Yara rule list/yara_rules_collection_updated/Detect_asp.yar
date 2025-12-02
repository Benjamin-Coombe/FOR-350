rule Detect_asp
{
    meta:
        description = "Regex detect pattern: .asp"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.asp/i
    condition:
        $regex
}
