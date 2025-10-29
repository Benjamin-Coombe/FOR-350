rule Detect_require_child_process_spawnSync
{
    meta:
        description = "String detect pattern: require('child_process').spawnSync("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('child_process').spawnSync(" nocase
    condition:
        $a
}
