rule Detect_require_vm_runInThisContext
{
    meta:
        description = "String detect pattern: require('vm').runInThisContext("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('vm').runInThisContext(" nocase
    condition:
        $a
}
