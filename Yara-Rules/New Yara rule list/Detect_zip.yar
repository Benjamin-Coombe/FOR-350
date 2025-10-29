rule Detect_zip
{
    meta:
        description = "String detect pattern: .zip"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".zip" nocase
    condition:
        $a
}
