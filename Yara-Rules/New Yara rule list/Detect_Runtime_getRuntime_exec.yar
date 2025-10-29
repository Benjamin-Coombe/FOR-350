rule Detect_Runtime_getRuntime_exec
{
    meta:
        description = "String detect pattern: Runtime.getRuntime(.exec("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Runtime.getRuntime(.exec(" nocase
    condition:
        $a
}
