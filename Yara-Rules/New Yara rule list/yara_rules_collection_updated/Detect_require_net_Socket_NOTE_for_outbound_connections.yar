rule Detect_require_net_Socket_NOTE_for_outbound_connections
{
    meta:
        description = "String detect pattern: require('net').Socket  NOTE: (for outbound connections)"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "require('net').Socket  NOTE: (for outbound connections)" nocase
    condition:
        $a
}
