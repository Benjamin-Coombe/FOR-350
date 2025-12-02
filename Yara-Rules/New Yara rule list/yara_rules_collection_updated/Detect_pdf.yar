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
