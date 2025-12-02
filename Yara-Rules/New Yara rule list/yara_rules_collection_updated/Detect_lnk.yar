rule Detect_lnk
{
    meta:
        description = "Detect Windows Shortcut LNK file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 } // LNK header
    condition:
        $lnk_magic at 0
}
