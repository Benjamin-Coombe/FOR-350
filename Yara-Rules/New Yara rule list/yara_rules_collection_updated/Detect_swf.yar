rule Detect_swf
{
    meta:
        description = "Detect Adobe Flash SWF file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $swf_uncompressed = { 46 57 53 } // FWS (uncompressed)
        $swf_compressed = { 43 57 53 } // CWS (compressed)
        $swf_lzma = { 5A 57 53 } // ZWS (LZMA compressed)
    condition:
        ($swf_uncompressed or $swf_compressed or $swf_lzma) at 0
}
