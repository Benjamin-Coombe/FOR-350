rule Detect_c_import_JSTL
{
    meta:
        description = "String detect pattern: c:import (JSTL)"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "c:import (JSTL)" nocase
    condition:
        $a
}
