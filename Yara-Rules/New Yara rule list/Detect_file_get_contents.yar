rule Detect_file_get_contents
{
    meta:
        description = "String detect pattern: file_get_contents("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "file_get_contents(" nocase
    condition:
        $a
}
