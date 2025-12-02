rule Detect_ppt
{
    meta:
        description = "Detect Microsoft PowerPoint PPT file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $ppt_magic = { D0 CF 11 E0 A1 B1 1A E1 } // OLE2 header (used by PPT)
    condition:
        $ppt_magic at 0
}
