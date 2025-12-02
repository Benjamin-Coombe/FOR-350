rule Detect_evtx
{
    meta:
        description = "Detect Windows Event Log EVTX file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $evtx_magic = { 45 6C 66 46 69 6C 65 00 } // ElfFile signature
    condition:
        $evtx_magic at 0
}
