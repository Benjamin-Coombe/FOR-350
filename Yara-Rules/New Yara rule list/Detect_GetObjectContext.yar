rule Detect_GetObjectContext
{
    meta:
        description = "String detect pattern: GetObjectContext("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "GetObjectContext(" nocase
    condition:
        $a
}
