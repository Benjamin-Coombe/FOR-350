rule Detect_cur
{
    meta:
        description = "Detect Windows Cursor CUR file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $cur_magic = { 00 00 02 00 } // CUR header
    condition:
        $cur_magic at 0
}
