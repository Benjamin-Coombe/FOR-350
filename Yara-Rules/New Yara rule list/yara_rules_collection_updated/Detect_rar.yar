rule Detect_rar
{
    meta:
        description = "Detect RAR archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $rar_magic = { 52 61 72 21 1A 07 } // RAR header (Rar!)
        $rar5_magic = { 52 61 72 21 1A 07 01 00 } // RAR5 header
    condition:
        $rar_magic at 0 or $rar5_magic at 0
}
