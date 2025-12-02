rule Detect_epub
{
    meta:
        description = "Detect EPUB e-book file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $epub_magic = { 50 4B 03 04 } // ZIP header (EPUB is ZIP-based)
        $mimetype = "mimetypeapplication/epub+zip" // EPUB mimetype
    condition:
        $epub_magic at 0 and $mimetype
}
