rule Detect_readpipe
{
    meta:
        description = "String detect pattern: readpipe("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "readpipe(" nocase
    condition:
        $a
}
