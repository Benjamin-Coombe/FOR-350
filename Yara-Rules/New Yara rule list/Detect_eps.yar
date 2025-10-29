rule Detect_eps
{
    meta:
        description = "Regex detect pattern: .eps"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.eps/i
    condition:
        $regex
}
