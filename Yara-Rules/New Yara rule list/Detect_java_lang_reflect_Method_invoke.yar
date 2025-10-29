rule Detect_java_lang_reflect_Method_invoke
{
    meta:
        description = "String detect pattern: java.lang.reflect.Method.invoke("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "java.lang.reflect.Method.invoke(" nocase
    condition:
        $a
}
