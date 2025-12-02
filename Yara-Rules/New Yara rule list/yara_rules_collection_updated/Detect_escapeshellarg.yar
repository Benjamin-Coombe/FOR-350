rule Detect_escapeshellarg
{
    meta:
        description = "String detect pattern: escapeshellarg("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "escapeshellarg(" nocase
    condition:
        $a
}
