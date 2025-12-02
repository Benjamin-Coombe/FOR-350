rule Detect_7z
{
    meta:
        description = "Detect 7-Zip archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $7z_magic = { 37 7A BC AF 27 1C } // 7z signature
    condition:
        $7z_magic at 0
}
