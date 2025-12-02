# YARA Rules Collection - Updated with Hex-Based File Detection

## Summary of Changes

This updated collection contains 120 YARA rules with **hex-based magic byte detection** for file type identification instead of string-based detection.

### Major Updates

#### 1. **Windows PE Executable Detection**

**32-bit Windows Executables** (`Detect_32_bit_exe_windows_file.yar`)
- Detects MZ header (`4D 5A`) at offset 0
- Verifies PE signature (`50 45 00 00`)
- Checks for 32-bit machine type (`4C 01` = IMAGE_FILE_MACHINE_I386)

**64-bit Windows Executables** (`Detect_64_bit_exe_windows_file.yar`)
- Detects MZ header (`4D 5A`) at offset 0
- Verifies PE signature (`50 45 00 00`)
- Checks for 64-bit machine type (`64 86` = IMAGE_FILE_MACHINE_AMD64)

#### 2. **ELF Executable Detection** (New)

**32-bit ELF Files** (`Detect_elf_32_bit`)
- Detects ELF magic bytes (`7F 45 4C 46`)
- Verifies ELFCLASS32 (value `01` at offset 4)

**64-bit ELF Files** (`Detect_elf_64_bit`)
- Detects ELF magic bytes (`7F 45 4C 46`)
- Verifies ELFCLASS64 (value `02` at offset 4)

**Any ELF File** (`Detect_elf_any`)
- Detects any ELF file regardless of architecture

#### 3. **Other File Types Updated with Hex Signatures**

All the following file types now use proper magic byte detection:

| File Type | Magic Bytes | Description |
|-----------|-------------|-------------|
| **PDF** | `25 50 44 46` | %PDF header |
| **ZIP** | `50 4B 03 04` | PK signature |
| **RAR** | `52 61 72 21 1A 07` | Rar! signature |
| **7-Zip** | `37 7A BC AF 27 1C` | 7z signature |
| **GZIP** | `1F 8B` | GZIP header |
| **DOC/XLS/PPT** | `D0 CF 11 E0 A1 B1 1A E1` | OLE2 header |
| **DOCX/XLSX/PPTX** | `50 4B 03 04` + content markers | ZIP-based Office files |
| **RTF** | `7B 5C 72 74 66` | {\rtf header |
| **JAR** | `50 4B 03 04` + META-INF | Java archive |
| **ISO** | `43 44 30 30 31` | CD001 signature |
| **LNK** | `4C 00 00 00 01 14 02 00` | Windows shortcut |
| **SWF** | `46 57 53` / `43 57 53` / `5A 57 53` | Flash file (FWS/CWS/ZWS) |
| **EPS** | `25 21 50 53 2D 41 64 6F 62 65` | %!PS-Adobe |
| **EPUB** | `50 4B 03 04` + mimetype | E-book format |
| **EVTX** | `45 6C 66 46 69 6C 65 00` | ElfFile signature |
| **VHD** | `63 6F 6E 65 63 74 69 78` | conectix signature |
| **VMDK** | `4B 44 4D` | VMware disk (KDM) |
| **QEMU** | `51 46 49 FB` | QCOW/QCOW2 |
| **MDB** | `00 01 00 00 53 74 61 6E 64 61 72 64...` | MS Access DB |
| **CUR** | `00 00 02 00` | Windows cursor |
| **DLL/SCR** | `4D 5A` + `50 45 00 00` | PE executables |

### Key Improvements

1. **Accuracy**: Hex-based detection is far more reliable than string matching
2. **Performance**: Direct byte matching is faster than string searches
3. **Architecture Detection**: Can now distinguish between 32-bit and 64-bit executables
4. **False Positive Reduction**: Magic bytes are much more specific than filename extensions
5. **Binary Format Support**: Properly detects file types even without extensions

### File Structure

```
yara_rules_collection_updated.zip
├── Detect_32_bit_exe_windows_file.yar (NEW: hex-based)
├── Detect_64_bit_exe_windows_file.yar (NEW: hex-based)
├── Detect_elf.yar (NEW: contains 3 rules for ELF detection)
├── Detect_exe.yar (UPDATED: hex-based PE detection)
├── Detect_dll.yar (UPDATED: hex-based PE detection)
├── Detect_pdf.yar (UPDATED: hex-based)
├── Detect_zip.yar (UPDATED: hex-based)
├── ... (30 filetype rules updated with hex signatures)
└── ... (88 other rules unchanged - for code patterns, functions, etc.)
```

### Usage Example

```yara
// The updated rules can be used like this:
yara Detect_32_bit_exe_windows_file.yar suspicious_file.exe
yara Detect_64_bit_exe_windows_file.yar suspicious_file.exe
yara Detect_elf_64_bit suspicious_binary
```

### Technical Notes

- **PE Detection**: Uses the MZ header at offset 0 and PE signature at the offset specified in the DOS header (typically 0x3C)
- **Machine Type**: Located at PE offset + 4 bytes
  - `0x014C` (little-endian: `4C 01`) = x86 (32-bit)
  - `0x8664` (little-endian: `64 86`) = x64 (64-bit)
- **ELF Detection**: EI_CLASS byte at offset 4 indicates architecture
  - `0x01` = 32-bit
  - `0x02` = 64-bit

### Compatibility

These rules are compatible with:
- YARA 4.x
- YARA 3.x (may need minor adjustments for some features)
- Command-line YARA
- YARA-Python
- Most YARA scanning tools

---

**Author**: Modified for hex detection  
**Date**: December 1, 2025  
**Original Collection**: ChatGPT-generated collection  
**Modification**: Converted string-based filetype detection to hex-based magic byte detection
