rule Detect_elf_32_bit
{
    meta:
        description = "Detect 32-bit ELF executable using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        // ELF magic: 7F 45 4C 46
        $elf_magic = { 7F 45 4C 46 }
        // 32-bit class (ELFCLASS32 = 1)
        $class_32 = { 01 }
    condition:
        $elf_magic at 0 and
        $class_32 at 4
}

rule Detect_elf_64_bit
{
    meta:
        description = "Detect 64-bit ELF executable using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        // ELF magic: 7F 45 4C 46
        $elf_magic = { 7F 45 4C 46 }
        // 64-bit class (ELFCLASS64 = 2)
        $class_64 = { 02 }
    condition:
        $elf_magic at 0 and
        $class_64 at 4
}

rule Detect_elf_any
{
    meta:
        description = "Detect any ELF executable (32-bit or 64-bit) using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        // ELF magic: 7F 45 4C 46
        $elf_magic = { 7F 45 4C 46 }
    condition:
        $elf_magic at 0
}
