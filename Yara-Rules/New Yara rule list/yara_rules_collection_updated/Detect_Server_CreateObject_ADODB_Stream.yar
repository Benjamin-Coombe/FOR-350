rule Detect_Server_CreateObject_ADODB_Stream
{
    meta:
        description = "String detect pattern: Server.CreateObject("ADODB.Stream")"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Server.CreateObject("ADODB.Stream")" nocase
    condition:
        $a
}
