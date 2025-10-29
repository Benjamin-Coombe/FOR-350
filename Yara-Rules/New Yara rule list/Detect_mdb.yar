rule Detect_mdb
{
    meta:
        description = "Regex detect pattern: .mdb"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.mdb/i
    condition:
        $regex
}
