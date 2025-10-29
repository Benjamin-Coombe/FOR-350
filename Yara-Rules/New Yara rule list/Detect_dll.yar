rule Detect_dll
{
    meta:
        description = "String detect pattern: .dll"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".dll" nocase
    condition:
        $a
}
