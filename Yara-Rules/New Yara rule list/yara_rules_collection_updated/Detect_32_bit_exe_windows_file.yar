rule Detect_32_bit_exe_windows_file
{
    meta:
        description = "Detect 32-bit Windows PE executable using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        // MZ header
        $mz = { 4D 5A }
        // PE signature at offset specified in MZ header (usually at 0x3C)
        // PE\0\0 signature
        $pe = { 50 45 00 00 }
        // 32-bit machine type (0x014C = IMAGE_FILE_MACHINE_I386)
        $machine_32 = { 4C 01 }
    condition:
        $mz at 0 and
        $pe and
        $machine_32 at (uint32(0x3C) + 4)
}
