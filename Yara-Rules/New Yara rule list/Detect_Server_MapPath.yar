rule Detect_Server_MapPath
{
    meta:
        description = "String detect pattern: Server.MapPath("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Server.MapPath(" nocase
    condition:
        $a
}
