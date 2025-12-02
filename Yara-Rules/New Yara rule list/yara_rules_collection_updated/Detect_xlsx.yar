rule Detect_xlsx
{
    meta:
        description = "Detect Microsoft Excel XLSX file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $xlsx_magic = { 50 4B 03 04 } // ZIP header (XLSX is ZIP-based)
        $xlsx_content = "xl/workbook.xml" // XLSX workbook indicator
    condition:
        $xlsx_magic at 0 and $xlsx_content
}
