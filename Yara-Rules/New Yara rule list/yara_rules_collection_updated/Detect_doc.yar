rule Detect_doc
{
    meta:
        description = "Detect Microsoft Word DOC file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $doc_magic = { D0 CF 11 E0 A1 B1 1A E1 } // OLE2 header (used by DOC)
    condition:
        $doc_magic at 0
}
