# YARA Rules Examples - Key File Type Detection

## Windows PE Executables

### 32-bit Windows Executable Detection

```yara
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
```

**What it detects:**
- Windows .exe files compiled for 32-bit (x86) architecture
- Windows .dll files (32-bit)
- Other PE files with 32-bit architecture

**Sample files it would match:**
- `calc.exe` (32-bit Windows Calculator)
- `notepad.exe` (32-bit version)
- Any 32-bit Windows executable

---

### 64-bit Windows Executable Detection

```yara
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
```

**What it detects:**
- Windows .exe files compiled for 64-bit (x64/AMD64) architecture
- Windows .dll files (64-bit)
- Other PE files with 64-bit architecture

**Sample files it would match:**
- Modern Windows executables on 64-bit systems
- `chrome.exe` (64-bit version)
- `firefox.exe` (64-bit version)

---

## ELF Executables (Linux/Unix)

### 32-bit ELF Detection

```yara
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
```

**What it detects:**
- Linux/Unix executables compiled for 32-bit
- Shared libraries (.so) files (32-bit)
- Other ELF format binaries (32-bit)

---

### 64-bit ELF Detection

```yara
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
```

**What it detects:**
- Linux/Unix executables compiled for 64-bit
- Modern Linux applications
- Shared libraries (.so) files (64-bit)

---

## Common Document Formats

### PDF Detection

```yara
rule Detect_pdf
{
    meta:
        description = "Detect PDF file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $pdf_magic = { 25 50 44 46 } // PDF header: %PDF
    condition:
        $pdf_magic at 0
}
```

**Hex breakdown:** `25 50 44 46` = `%PDF` (ASCII)

---

### Microsoft Office DOCX

```yara
rule Detect_docx
{
    meta:
        description = "Detect Microsoft Word DOCX file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $docx_magic = { 50 4B 03 04 } // ZIP header (DOCX is ZIP-based)
        $docx_content = "[Content_Types].xml" // DOCX content indicator
    condition:
        $docx_magic at 0 and $docx_content
}
```

**Note:** DOCX files are actually ZIP archives containing XML files

---

## Archive Formats

### ZIP Detection

```yara
rule Detect_zip
{
    meta:
        description = "Detect ZIP archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $zip_magic = { 50 4B 03 04 } // ZIP header (PK)
        $zip_empty = { 50 4B 05 06 } // Empty ZIP archive
        $zip_spanned = { 50 4B 07 08 } // Spanned ZIP archive
    condition:
        $zip_magic at 0 or $zip_empty at 0 or $zip_spanned at 0
}
```

**Hex breakdown:** `50 4B` = `PK` (initials of Phil Katz, ZIP creator)

---

### RAR Detection

```yara
rule Detect_rar
{
    meta:
        description = "Detect RAR archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $rar_magic = { 52 61 72 21 1A 07 } // RAR header (Rar!)
        $rar5_magic = { 52 61 72 21 1A 07 01 00 } // RAR5 header
    condition:
        $rar_magic at 0 or $rar5_magic at 0
}
```

**Hex breakdown:** `52 61 72 21` = `Rar!` (ASCII)

---

## Usage Examples

### Command Line

```bash
# Scan a single file
yara Detect_64_bit_exe_windows_file.yar suspicious.exe

# Scan a directory
yara -r Detect_elf_64_bit.yar /usr/bin/

# Use all rules in a directory
yara -r /path/to/rules/ /path/to/scan/

# Get detailed output
yara -s Detect_32_bit_exe_windows_file.yar malware_sample.exe
```

### Python Example

```python
import yara

# Compile rules
rules = yara.compile(filepath='Detect_64_bit_exe_windows_file.yar')

# Scan a file
matches = rules.match('/path/to/file.exe')

# Check results
if matches:
    print(f"File matched: {matches[0].rule}")
    print(f"Description: {matches[0].meta['description']}")
```

---

## Testing Your Rules

### Create Test Files

```bash
# Create a simple PE header (won't run, just for detection)
echo -ne '\x4D\x5A' > test_pe.exe

# Create an ELF header
echo -ne '\x7F\x45\x4C\x46' > test_elf

# Create a PDF header
echo '%PDF-1.4' > test.pdf

# Test with YARA
yara Detect_exe.yar test_pe.exe
yara Detect_elf_any.yar test_elf
yara Detect_pdf.yar test.pdf
```

---

## Why Hex Detection is Better

### Old Method (String-based)
```yara
strings:
    $a = ".exe" nocase
condition:
    $a
```
**Problems:**
- Matches text files containing ".exe"
- Matches URLs with ".exe"
- Doesn't actually verify it's an executable

### New Method (Hex-based)
```yara
strings:
    $mz = { 4D 5A }
    $pe = { 50 45 00 00 }
condition:
    $mz at 0 and $pe
```
**Advantages:**
- Only matches actual PE executables
- Checks file structure, not content
- Much more accurate and reliable

---

## Quick Reference: Common Magic Bytes

| Format | Hex Signature | ASCII Equivalent |
|--------|---------------|------------------|
| PE (EXE/DLL) | `4D 5A` | MZ |
| ELF | `7F 45 4C 46` | .ELF |
| PDF | `25 50 44 46` | %PDF |
| ZIP | `50 4B 03 04` | PK |
| PNG | `89 50 4E 47` | .PNG |
| JPEG | `FF D8 FF` | (binary) |
| GIF | `47 49 46 38` | GIF8 |
| RAR | `52 61 72 21` | Rar! |
| 7-Zip | `37 7A BC AF 27 1C` | 7z |
| GZIP | `1F 8B` | (binary) |

