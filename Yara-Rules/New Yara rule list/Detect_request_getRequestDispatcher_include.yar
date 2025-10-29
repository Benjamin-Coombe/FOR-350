rule Detect_request_getRequestDispatcher_include
{
    meta:
        description = "String detect pattern: request.getRequestDispatcher(.include("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "request.getRequestDispatcher(.include(" nocase
    condition:
        $a
}
