rule Detect_Server_CreateObject_Shell_Application
{
    meta:
        description = "String detect pattern: Server.CreateObject("Shell.Application")"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Server.CreateObject("Shell.Application")" nocase
    condition:
        $a
}
