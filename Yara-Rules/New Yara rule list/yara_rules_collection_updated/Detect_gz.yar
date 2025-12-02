rule Detect_gz
{
    meta:
        description = "Detect GZIP archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $gz_magic = { 1F 8B } // GZIP header
    condition:
        $gz_magic at 0
}
