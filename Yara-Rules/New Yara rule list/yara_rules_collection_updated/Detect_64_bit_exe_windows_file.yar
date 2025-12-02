rule Detect_64_bit_exe_windows_file
{
    meta:
        description = "Detect 64-bit Windows PE executable using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        // MZ header
        $mz = { 4D 5A }
        // PE signature
        $pe = { 50 45 00 00 }
        // 64-bit machine type (0x8664 = IMAGE_FILE_MACHINE_AMD64)
        $machine_64 = { 64 86 }
    condition:
        $mz at 0 and
        $pe and
        $machine_64 at (uint32(0x3C) + 4)
}
