rule Detect_scr
{
    meta:
        description = "Detect Windows Screensaver SCR file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $mz = { 4D 5A } // MZ header (SCR is executable)
        $pe = { 50 45 00 00 } // PE signature
    condition:
        $mz at 0 and $pe
}
