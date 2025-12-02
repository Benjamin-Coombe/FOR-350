rule Detect_ScriptControl_ExecuteStatement
{
    meta:
        description = "String detect pattern: ScriptControl.ExecuteStatement"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "ScriptControl.ExecuteStatement" nocase
    condition:
        $a
}
