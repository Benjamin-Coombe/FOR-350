rule Detect_evtx
{
    meta:
        description = "Regex detect pattern: .evtx"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.evtx/i
    condition:
        $regex
}
