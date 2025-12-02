rule Detect_IO_Socket
{
    meta:
        description = "String detect pattern: IO::Socket"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "IO::Socket" nocase
    condition:
        $a
}
