rule Packer_ASPack
{
    meta:
        description = "Detects files packed with ASPack"
        author = "ChatGPT"
        packer = "ASPack"

    strings:
        $a1 = "ASPack" ascii
        $a2 = "ASPack v" ascii
        $a3 = { 41 53 50 61 63 6B } // "ASPack"

    condition:
        any of ($a*)
}