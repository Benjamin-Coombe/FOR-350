rule Detect_iso
{
    meta:
        description = "Regex detect pattern: .iso"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.iso/i
    condition:
        $regex
}
