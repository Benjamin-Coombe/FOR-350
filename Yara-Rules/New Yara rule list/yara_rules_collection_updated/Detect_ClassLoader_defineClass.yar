rule Detect_ClassLoader_defineClass
{
    meta:
        description = "String detect pattern: ClassLoader.defineClass("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "ClassLoader.defineClass(" nocase
    condition:
        $a
}
