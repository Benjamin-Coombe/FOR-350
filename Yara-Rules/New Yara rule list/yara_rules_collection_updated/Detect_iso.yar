rule Detect_iso
{
    meta:
        description = "Detect ISO 9660 CD/DVD image using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $iso_magic1 = { 43 44 30 30 31 } // CD001 signature
        $iso_magic2 = { 43 44 30 30 31 01 } // Extended CD001
    condition:
        $iso_magic1 or $iso_magic2
}
