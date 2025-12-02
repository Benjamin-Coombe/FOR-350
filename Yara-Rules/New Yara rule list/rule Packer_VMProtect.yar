rule Packer_VMProtect
{
    meta:
        description = "Detects files protected with VMProtect"
        author = "ChatGPT"
        packer = "VMProtect"

    strings:
        $v1 = "VMProtect" ascii
        $v2 = "VP_VIRTUALIZATION" ascii
        $v3 = "VMProtectSDK" ascii

    condition:
        any of ($v*)
}