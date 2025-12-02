rule Detect_open_with_pipe_e_g_open_FILE_command
{
    meta:
        description = "String detect pattern: open( with pipe (e.g., open(FILE, "command|"))"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "open( with pipe (e.g., open(FILE, "command|"))" nocase
    condition:
        $a
}
