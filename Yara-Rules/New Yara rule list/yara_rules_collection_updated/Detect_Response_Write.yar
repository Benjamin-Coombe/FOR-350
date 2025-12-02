rule Detect_Response_Write
{
    meta:
        description = "String detect pattern: Response.Write("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Response.Write(" nocase
    condition:
        $a
}
