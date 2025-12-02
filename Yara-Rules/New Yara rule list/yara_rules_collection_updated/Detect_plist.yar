rule Detect_plist
{
    meta:
        description = "Detect Apple Property List file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $plist_xml = { 3C 3F 78 6D 6C } // XML declaration: <?xml
        $plist_binary = { 62 70 6C 69 73 74 30 30 } // Binary plist: bplist00
    condition:
        $plist_binary at 0 or ($plist_xml at 0 and $plist_content)
}
