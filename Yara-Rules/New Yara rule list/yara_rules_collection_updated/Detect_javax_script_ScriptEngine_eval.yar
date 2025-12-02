rule Detect_javax_script_ScriptEngine_eval
{
    meta:
        description = "String detect pattern: javax.script.ScriptEngine.eval("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "javax.script.ScriptEngine.eval(" nocase
    condition:
        $a
}
