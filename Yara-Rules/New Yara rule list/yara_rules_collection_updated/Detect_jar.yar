rule Detect_jar
{
    meta:
        description = "Detect Java JAR archive using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $jar_magic = { 50 4B 03 04 } // ZIP header (JAR is ZIP-based)
        $manifest = "META-INF/MANIFEST.MF" // JAR manifest
    condition:
        $jar_magic at 0 and $manifest
}
