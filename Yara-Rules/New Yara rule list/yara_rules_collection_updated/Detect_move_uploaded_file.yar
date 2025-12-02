rule Detect_move_uploaded_file
{
    meta:
        description = "String detect pattern: move_uploaded_file("
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "move_uploaded_file(" nocase
    condition:
        $a
}
