rule Detect_require_vm_runInNewContext
{
    meta:
        description = "String detect pattern: require('vm').runInNewContext("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('vm').runInNewContext(" nocase
    condition:
        $a
}
