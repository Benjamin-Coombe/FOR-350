rule Detect_vmdk
{
    meta:
        description = "Regex detect pattern: .vmdk"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.vmdk/i
    condition:
        $regex
}
