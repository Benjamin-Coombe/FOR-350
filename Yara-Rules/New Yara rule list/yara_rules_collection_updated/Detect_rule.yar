rule Detect_rule
{
    meta:
        description = "Regex detect pattern: ."
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\./i
    condition:
        $regex
}
