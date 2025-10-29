rule Detect_new_java_io_FileOutputStream
{
    meta:
        description = "String detect pattern: new java.io.FileOutputStream("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "new java.io.FileOutputStream(" nocase
    condition:
        $a
}
