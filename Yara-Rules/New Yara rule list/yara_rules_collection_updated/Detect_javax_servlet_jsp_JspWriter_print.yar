rule Detect_javax_servlet_jsp_JspWriter_print
{
    meta:
        description = "String detect pattern: javax.servlet.jsp.JspWriter.print("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "javax.servlet.jsp.JspWriter.print(" nocase
    condition:
        $a
}
