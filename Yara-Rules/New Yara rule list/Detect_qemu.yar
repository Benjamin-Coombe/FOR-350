rule Detect_qemu
{
    meta:
        description = "Regex detect pattern: .qemu"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.qemu/i
    condition:
        $regex
}
