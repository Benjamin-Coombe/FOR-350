rule Detect_rar
{
    meta:
        description = "String detect pattern: .rar"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = ".rar" nocase
    condition:
        $a
}
