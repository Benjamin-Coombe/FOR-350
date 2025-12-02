rule Detect_eps
{
    meta:
        description = "Detect Encapsulated PostScript file using magic bytes"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $eps_magic = { 25 21 50 53 2D 41 64 6F 62 65 } // EPS header: %!PS-Adobe
        $eps_binary = { C5 D0 D3 C6 } // EPS binary header
    condition:
        $eps_magic at 0 or $eps_binary at 0
}
