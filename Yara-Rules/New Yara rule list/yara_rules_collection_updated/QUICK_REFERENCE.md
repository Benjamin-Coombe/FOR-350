# Quick Reference Card - Essential YARA Rules

## Architecture Detection Cheat Sheet

### Windows Executables

```bash
# Detect 32-bit Windows PE
yara Detect_32_bit_exe_windows_file.yar target.exe

# Detect 64-bit Windows PE  
yara Detect_64_bit_exe_windows_file.yar target.exe

# Detect any Windows PE (generic)
yara Detect_exe.yar target.exe
```

**Key Hex Signatures:**
- MZ Header: `4D 5A` (offset 0)
- PE Signature: `50 45 00 00` (variable offset)
- 32-bit: `4C 01` (machine type at PE+4)
- 64-bit: `64 86` (machine type at PE+4)

### Linux/Unix ELF Executables

```bash
# Detect 32-bit ELF
yara Detect_elf_32_bit.yar binary

# Detect 64-bit ELF
yara Detect_elf_64_bit.yar binary

# Detect any ELF file
yara Detect_elf_any.yar binary
```

**Key Hex Signatures:**
- ELF Magic: `7F 45 4C 46` (offset 0)
- 32-bit: `01` (offset 4)
- 64-bit: `02` (offset 4)

## Most Common File Types

| Format | Rule File | Hex Signature |
|--------|-----------|---------------|
| **PDF** | Detect_pdf.yar | `25 50 44 46` |
| **ZIP** | Detect_zip.yar | `50 4B 03 04` |
| **RAR** | Detect_rar.yar | `52 61 72 21` |
| **7-Zip** | Detect_7z.yar | `37 7A BC AF` |
| **GZIP** | Detect_gz.yar | `1F 8B` |

## Batch Scanning Examples

```bash
# Scan entire directory for 64-bit executables
yara -r Detect_64_bit_exe_windows_file.yar /path/to/scan/

# Scan for any ELF files
yara -r Detect_elf_any.yar /usr/bin/

# Use multiple rules
yara -r Detect_32_bit_exe_windows_file.yar \
        Detect_64_bit_exe_windows_file.yar \
        Detect_elf_64_bit.yar malware_samples/

# Get detailed output with matched strings
yara -s Detect_32_bit_exe_windows_file.yar suspicious.exe
```

## Python Integration

```python
import yara

# Load rules
rules = yara.compile(filepaths={
    'pe32': 'Detect_32_bit_exe_windows_file.yar',
    'pe64': 'Detect_64_bit_exe_windows_file.yar',
    'elf32': 'Detect_elf_32_bit.yar',
    'elf64': 'Detect_elf_64_bit.yar',
})

# Scan file
matches = rules.match('suspicious_binary')

# Check results
for match in matches:
    print(f"Matched: {match.rule}")
    print(f"Type: {match.meta['description']}")
```

## Identifying Architecture of Unknown Binary

```bash
# Create a simple script
cat > identify_arch.sh << 'EOF'
#!/bin/bash
FILE=$1

echo "Analyzing: $FILE"
echo "===================="

if yara -q Detect_32_bit_exe_windows_file.yar "$FILE" 2>/dev/null; then
    echo "✓ 32-bit Windows PE executable"
elif yara -q Detect_64_bit_exe_windows_file.yar "$FILE" 2>/dev/null; then
    echo "✓ 64-bit Windows PE executable"
elif yara -q Detect_elf_32_bit.yar "$FILE" 2>/dev/null; then
    echo "✓ 32-bit ELF executable"
elif yara -q Detect_elf_64_bit.yar "$FILE" 2>/dev/null; then
    echo "✓ 64-bit ELF executable"
else
    echo "✗ Unknown or not an executable"
fi
EOF

chmod +x identify_arch.sh
./identify_arch.sh mystery_file
```

## Common Use Cases

### 1. Malware Analysis
```bash
# Check if suspicious file is 32-bit or 64-bit
yara Detect_32_bit_exe_windows_file.yar malware.bin
yara Detect_64_bit_exe_windows_file.yar malware.bin
```

### 2. File Classification
```bash
# Classify files in a directory by actual type (not extension)
for f in *; do
    echo -n "$f: "
    yara -q Detect_exe.yar "$f" && echo "PE executable" && continue
    yara -q Detect_pdf.yar "$f" && echo "PDF" && continue
    yara -q Detect_zip.yar "$f" && echo "ZIP" && continue
    echo "Unknown"
done
```

### 3. Security Scanning
```bash
# Find all executables (regardless of extension)
find /suspicious/directory -type f -exec \
    yara -q Detect_exe.yar {} \; -print

# Find 64-bit ELF files that might be malware
find /tmp -type f -exec \
    yara -q Detect_elf_64_bit.yar {} \; -print
```

## Key Differences from Old Rules

### OLD (String-based):
```yara
strings:
    $a = ".exe" nocase
condition:
    $a
```
❌ Matches: "Click here to download game.exe from our site"  
❌ Matches: URLs, logs, any text containing ".exe"

### NEW (Hex-based):
```yara
strings:
    $mz = { 4D 5A }
    $pe = { 50 45 00 00 }
condition:
    $mz at 0 and $pe
```
✅ Only matches: Actual PE executable files  
✅ Validates: Binary structure at specific offsets

## Tips & Tricks

1. **Combine rules for better detection:**
   ```bash
   yara Detect_32_bit_exe_windows_file.yar suspicious.bin && \
   echo "Found 32-bit executable"
   ```

2. **Use -s flag to see matched bytes:**
   ```bash
   yara -s Detect_64_bit_exe_windows_file.yar file.exe
   ```

3. **Recursive scanning with output:**
   ```bash
   yara -r Detect_elf_64_bit.yar /path/ > elf64_files.txt
   ```

4. **Check multiple architectures:**
   ```bash
   yara -r Detect_32_bit_exe_windows_file.yar \
           Detect_64_bit_exe_windows_file.yar \
           suspicious_directory/
   ```

## Memory/Performance Notes

- Hex-based detection is **faster** than string matching
- Rules check specific offsets (very efficient)
- Can scan thousands of files quickly
- Low false positive rate

## Need Help?

See the full documentation:
- **README.md** - Complete overview
- **EXAMPLES.md** - Detailed examples
- **CHANGES.txt** - What changed from original

---

**Quick Start:** Extract the zip, navigate to the directory, and run:
```bash
yara Detect_64_bit_exe_windows_file.yar /path/to/file
```
