rule Detect_xls
{
    meta:
        description = "Detect Microsoft Excel XLS file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $xls_magic = { D0 CF 11 E0 A1 B1 1A E1 } // OLE2 header (used by XLS)
    condition:
        $xls_magic at 0
}
