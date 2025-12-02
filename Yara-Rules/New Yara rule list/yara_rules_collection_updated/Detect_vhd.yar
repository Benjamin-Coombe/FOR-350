rule Detect_vhd
{
    meta:
        description = "Detect Virtual Hard Disk VHD file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $vhd_magic = { 63 6F 6E 65 63 74 69 78 } // conectix signature
    condition:
        $vhd_magic
}
