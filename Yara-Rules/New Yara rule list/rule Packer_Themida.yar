rule Packer_Themida
{
    meta:
        description = "Detects files protected with Themida"
        author = "ChatGPT"
        packer = "Themida"

    strings:
        $t1 = "Themida" ascii
        $t2 = "WinLicense" ascii
        $t3 = "Protected by Themida" ascii
        $t4 = { 54 68 65 6D 69 64 61 }  // "Themida"

    condition:
        any of ($t*)
}