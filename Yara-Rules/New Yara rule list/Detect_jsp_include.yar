rule Detect_jsp_include
{
    meta:
        description = "String detect pattern: jsp:include"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "jsp:include" nocase
    condition:
        $a
}
