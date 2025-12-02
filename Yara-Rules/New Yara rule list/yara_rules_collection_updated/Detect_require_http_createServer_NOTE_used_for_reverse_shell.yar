rule Detect_require_http_createServer_NOTE_used_for_reverse_shell
{
    meta:
        description = "String detect pattern: require('http').createServer(  NOTE(used for reverse shell)"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('http').createServer(  NOTE(used for reverse shell)" nocase
    condition:
        $a
}
