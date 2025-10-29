rule Detect_ScriptControl_Eval
{
    meta:
        description = "String detect pattern: ScriptControl.Eval"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "ScriptControl.Eval" nocase
    condition:
        $a
}
