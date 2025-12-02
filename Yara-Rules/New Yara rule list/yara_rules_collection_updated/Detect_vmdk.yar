rule Detect_vmdk
{
    meta:
        description = "Detect VMware Virtual Disk VMDK file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $vmdk_magic = { 4B 44 4D } // KDM signature
        $vmdk_descriptor = "# Disk DescriptorFile" // VMDK descriptor
    condition:
        $vmdk_magic at 0 or $vmdk_descriptor at 0
}
