rule Detect_Server_CreateObject_WScript_Shell
{
    meta:
        description = "String detect pattern: Server.CreateObject("WScript.Shell")"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Server.CreateObject("WScript.Shell")" nocase
    condition:
        $a
}
