rule Detect_eml
{
    meta:
        description = "Regex detect pattern: .eml"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.eml/i
    condition:
        $regex
}
