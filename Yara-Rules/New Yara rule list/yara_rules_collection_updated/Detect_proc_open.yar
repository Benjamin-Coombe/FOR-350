rule Detect_proc_open
{
    meta:
        description = "String detect pattern: proc_open("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "proc_open(" nocase
    condition:
        $a
}
