rule Detect_Server_Execute
{
    meta:
        description = "String detect pattern: Server.Execute("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Server.Execute(" nocase
    condition:
        $a
}
