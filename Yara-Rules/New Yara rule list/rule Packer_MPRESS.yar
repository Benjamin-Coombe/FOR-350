rule Packer_MPRESS
{
    meta:
        description = "Detects files packed with MPRESS"
        author = "ChatGPT"
        packer = "MPRESS"

    strings:
        $s1 = "MPRESS1" ascii
        $s2 = "MPRESS2" ascii
        $s3 = { 4D 50 52 45 53 }  // "MPRES"

    condition:
        any of ($s*)
}