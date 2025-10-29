rule Detect_java_net_Socket_for_reverse_bind_shells
{
    meta:
        description = "String detect pattern: java.net.Socket (for reverse/bind shells)"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "java.net.Socket (for reverse/bind shells)" nocase
    condition:
        $a
}
