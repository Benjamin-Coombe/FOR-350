rule Detect_socket
{
    meta:
        description = "String detect pattern: socket("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "socket(" nocase
    condition:
        $a
}
