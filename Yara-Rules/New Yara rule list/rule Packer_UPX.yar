rule Packer_UPX
{
    meta:
        description = "Detects files packed with UPX"
        author = "ChatGPT"
        packer = "UPX"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii

    condition:
        1 of ($upx*)
}