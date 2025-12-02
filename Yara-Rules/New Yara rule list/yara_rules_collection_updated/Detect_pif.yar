rule Detect_pif
{
    meta:
        description = "Detect Program Information File (DOS) using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $mz = { 4D 5A } // MZ header (PIF can be executable)
    condition:
        $mz at 0
}
