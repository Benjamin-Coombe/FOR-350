rule Detect_qemu
{
    meta:
        description = "Detect QEMU disk image using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $qcow_magic = { 51 46 49 FB } // QFI signature (QCOW)
        $qcow2_magic = { 51 46 49 FB 00 00 00 02 } // QCOW2 signature
    condition:
        $qcow_magic at 0 or $qcow2_magic at 0
}
