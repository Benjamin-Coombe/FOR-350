rule Detect_mdb
{
    meta:
        description = "Detect Microsoft Access MDB file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $mdb_magic = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 } // Standard Jet DB
    condition:
        $mdb_magic at 0
}
