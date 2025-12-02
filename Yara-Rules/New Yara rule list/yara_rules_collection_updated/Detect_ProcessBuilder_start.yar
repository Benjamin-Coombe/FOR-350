rule Detect_ProcessBuilder_start
{
    meta:
        description = "String detect pattern: ProcessBuilder.start("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "ProcessBuilder.start(" nocase
    condition:
        $a
}
