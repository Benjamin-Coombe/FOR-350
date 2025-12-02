rule Detect_pptx
{
    meta:
        description = "Detect Microsoft PowerPoint PPTX file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $pptx_magic = { 50 4B 03 04 } // ZIP header (PPTX is ZIP-based)
        $pptx_content = "ppt/presentation.xml" // PPTX presentation indicator
    condition:
        $pptx_magic at 0 and $pptx_content
}
