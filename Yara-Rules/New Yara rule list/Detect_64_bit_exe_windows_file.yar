rule Detect_64_bit_exe_windows_file
{
    meta:
        description = "Regex detect pattern: 64-bit .exe windows file"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /64\-bit\ \.exe\ windows\ file/i
    condition:
        $regex
}
