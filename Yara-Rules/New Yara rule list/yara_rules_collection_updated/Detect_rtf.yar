rule Detect_rtf
{
    meta:
        description = "Detect Rich Text Format file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $rtf_magic = { 7B 5C 72 74 66 } // RTF header: {\rtf
    condition:
        $rtf_magic at 0
}
