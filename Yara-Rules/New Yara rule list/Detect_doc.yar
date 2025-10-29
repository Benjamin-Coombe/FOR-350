rule Detect_doc
{
    meta:
        description = "Regex detect pattern: .doc"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.doc/i
    condition:
        $regex
}
