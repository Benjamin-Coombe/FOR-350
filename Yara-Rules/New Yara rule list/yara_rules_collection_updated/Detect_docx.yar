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
