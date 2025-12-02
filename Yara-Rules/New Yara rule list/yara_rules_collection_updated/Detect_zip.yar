rule Detect_zip
{
    meta:
        description = "Detect ZIP archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $zip_magic = { 50 4B 03 04 } // ZIP header (PK)
        $zip_empty = { 50 4B 05 06 } // Empty ZIP archive
        $zip_spanned = { 50 4B 07 08 } // Spanned ZIP archive
    condition:
        $zip_magic at 0 or $zip_empty at 0 or $zip_spanned at 0
}
