rule Detect_new_java_io_PrintWriter
{
    meta:
        description = "String detect pattern: new java.io.PrintWriter("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "new java.io.PrintWriter(" nocase
    condition:
        $a
}
