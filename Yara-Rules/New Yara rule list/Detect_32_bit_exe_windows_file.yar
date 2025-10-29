rule Detect_32_bit_exe_windows_file
{
    meta:
        description = "Regex detect pattern: 32-bit .exe windows file"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /32\-bit\ \.exe\ windows\ file/i
    condition:
        $regex
}
