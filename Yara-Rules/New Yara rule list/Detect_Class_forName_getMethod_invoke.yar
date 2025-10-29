rule Detect_Class_forName_getMethod_invoke
{
    meta:
        description = "String detect pattern: Class.forName(.getMethod(.invoke("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Class.forName(.getMethod(.invoke(" nocase
    condition:
        $a
}
