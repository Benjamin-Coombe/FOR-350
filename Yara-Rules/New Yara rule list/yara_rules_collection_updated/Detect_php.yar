rule Detect_php
{
    meta:
        description = "Regex detect pattern: .php"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.php/i
    condition:
        $regex
}
