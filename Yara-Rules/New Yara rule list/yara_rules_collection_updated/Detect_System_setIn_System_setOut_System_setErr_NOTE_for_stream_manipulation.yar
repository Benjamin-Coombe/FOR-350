rule Detect_System_setIn_System_setOut_System_setErr_NOTE_for_stream_manipulation
{
    meta:
        description = "String detect pattern: System.setIn(, System.setOut(, System.setErr(   NOTE: (for stream manipulation)"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "System.setIn(, System.setOut(, System.setErr(   NOTE: (for stream manipulation)" nocase
    condition:
        $a
}
