rule Detect_exe
{
    meta:
        description = "String detect pattern: .exe"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".exe" nocase
    condition:
        $a
}
